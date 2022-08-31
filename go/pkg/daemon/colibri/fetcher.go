// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package colibri

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
)

type Fetcher interface {
	ListReservations(ctx context.Context, req *sdpb.ColibriListRsvsRequest) (
		*sdpb.ColibriListRsvsResponse, error)
}

func NewFetcher(dialer grpc.Dialer) Fetcher {
	return &defaultFetcher{
		dialer: dialer,
		cache: &rsvCache{
			entries: make(map[addr.IA]*entry),
		},
	}
}

const (
	maxDurIsFresh   = time.Minute                    // entry in cache is valid for this long
	waitDuration    = maxDurIsFresh - 10*time.Second // time between rsv updates
	rsvLifeDuration = 5 * time.Minute                // keep updating the rsv for this long
)

type defaultFetcher struct {
	dialer     grpc.Dialer
	cache      *rsvCache
	fetchDedup singleflight.Group
}

// ListReservations will dial to the intra AS colibri service to get the list of rsvs if the
// list cannot be found inside the cache.
// The entry is kept alive and fresh for `rsvLifeDuration`, and every time a new query
// to the same dstIA is made, the life of the listing is reset.
func (f *defaultFetcher) ListReservations(ctx context.Context, req *sdpb.ColibriListRsvsRequest) (
	*sdpb.ColibriListRsvsResponse, error) {

	if req == nil {
		return nil, serrors.New("bad nil request")
	}
	return f.listReservations(ctx, req)
}

func (f *defaultFetcher) listReservations(ctx context.Context, req *sdpb.ColibriListRsvsRequest) (
	*sdpb.ColibriListRsvsResponse, error) {

	dstIA := addr.IA(req.Base.DstIa)
	f.sheperd(dstIA, req)

	if res, ok := f.cache.ListReservations(ctx, dstIA); ok {
		return res, nil
	}
	return f.fetch(ctx, dstIA, &f.fetchDedup, req)
}

func (f *defaultFetcher) fetch(ctx context.Context, dstIA addr.IA, dedup *singleflight.Group,
	req *sdpb.ColibriListRsvsRequest) (*sdpb.ColibriListRsvsResponse, error) {

	r, err, _ := dedup.Do(dstIA.String(), func() (interface{}, error) {
		log.Debug("fetching list of stitchables", "dst", dstIA.String())
		conn, err := f.dialer.Dial(ctx, addr.SvcCOL)
		if err != nil {
			return nil, err
		}
		client := colpb.NewColibriServiceClient(conn) // TODO(juagargi) cache the client
		response, err := client.ListStitchables(ctx, req.Base)
		return &sdpb.ColibriListRsvsResponse{Base: response}, err
	})
	response, _ := r.(*sdpb.ColibriListRsvsResponse)
	return response, err
}

// sheperd will take care of the listing for this destination, for a period of time.
// It checks in the cache the existence of the listing or creates it. It keeps updating it for
// a while, specified by waitDuration and maxUpdateDuration.
func (f *defaultFetcher) sheperd(dstIA addr.IA, req *sdpb.ColibriListRsvsRequest) {
	e, found := f.cache.FindOrCreate(dstIA)
	if found {
		// there exists a possibility of being here without e being actually inside the cache,
		// but it won't matter anyways.
		e.added = time.Now()
		return
	}
	// `e` has been newly created in the cache. Populate and shepperd it
	e.added = time.Now()
	go func() {
		defer log.HandlePanic()
		for {
			if time.Now().After(e.added.Add(rsvLifeDuration)) {
				break
			}
			ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
			res, err := f.fetch(ctx, dstIA, &f.fetchDedup, req)
			cancelF()
			if err != nil {
				log.Info("error keeping destination listing updated", "err", err)
			} else {
				e.response = res
			}
			time.Sleep(waitDuration)
		}
		// clean the entry once it's expired
		sleepiness := time.Until(e.added.Add(maxDurIsFresh))
		time.Sleep(sleepiness)
		log.Debug("deleting expired colibri reservation listing", "dst", dstIA.String())
		f.cache.DeleteEntry(dstIA)
	}()
}

// rsvCache uses a map to keep a copy of the reservation list per destination.
// It is not backed up by a DB.
type rsvCache struct {
	entries map[addr.IA]*entry
	m       sync.Mutex
}

// ListReservations returns the list of reservations and a boolean indicating whether the
// cache had them or not.
func (c *rsvCache) ListReservations(ctx context.Context, dstIA addr.IA) (
	*sdpb.ColibriListRsvsResponse, bool) {

	c.m.Lock()
	defer c.m.Unlock()

	if e, ok := c.entries[dstIA]; ok {
		if e.added.Add(maxDurIsFresh).Before(time.Now()) {
			return e.response, true
		}
		// delete(c.entries, dstIA)
	}
	return nil, false
}

// FindOrCreate returns the always non nil entry, and a boolean indicating if
// the entry was present already in the cache.
func (c *rsvCache) FindOrCreate(dstIA addr.IA) (*entry, bool) {
	c.m.Lock()
	defer c.m.Unlock()

	e, ok := c.entries[dstIA]
	if !ok {
		e = &entry{}
		c.entries[dstIA] = e
	}
	return e, ok
}

func (c *rsvCache) DeleteEntry(dstIA addr.IA) {
	c.m.Lock()
	defer c.m.Unlock()

	delete(c.entries, dstIA)
}

type entry struct {
	added    time.Time
	response *sdpb.ColibriListRsvsResponse
}
