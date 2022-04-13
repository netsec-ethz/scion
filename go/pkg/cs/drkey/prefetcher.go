// Copyright 2019 ETH Zurich
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

package drkey

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

// Lvl1PrefetchListKeeper maintains a likst for those lvl1 keys
// that are recently/frequently used
type Lvl1PrefetchListKeeper interface {
	//Update updates the keys in Lvl1Cache based on the Lvl1Key metadata
	Update(key Lvl1PrefetchInfo)
	// GetLvl1InfoArray retrieves an array whose memebers contains information regarding
	// lvl1 keys to prefetch
	GetLvl1InfoArray() []Lvl1PrefetchInfo
}

// Lvl1PrefetchInfo contains the information to prefetch lvl1 keys from remote CSes.
type Lvl1PrefetchInfo struct {
	IA    addr.IA
	Proto drkey.Protocol
}

var _ periodic.Task = (*Prefetcher)(nil)

// Prefetcher is in charge of getting the level 1 keys before they expire.
type Prefetcher struct {
	LocalIA addr.IA
	Engine  ServiceEngine
	// XXX(JordiSubira): At the moment we assume "global" KeyDuration, i.e.
	// every AS involved uses the same EpochDuration. This will be improve
	// further in the future, so that the prefetcher get keys in advance
	// based on the epoch established by the AS which derived the first
	// level key.
	KeyDuration time.Duration
}

// Name returns the tasks name.
func (f *Prefetcher) Name() string {
	return "drkey.Prefetcher"
}

// Run requests the level 1 keys to other CSs.
func (f *Prefetcher) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	var wg sync.WaitGroup
	ases := f.Engine.GetLvl1PrefetchInfo()
	logger.Debug("Prefetching level 1 DRKeys", "ASes", ases)
	when := time.Now().Add(f.KeyDuration)
	for _, key := range ases {
		key := key
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			getLvl1Key(ctx, f.Engine, key.IA, f.LocalIA, key.Proto, when, &wg)
		}()
	}
	wg.Wait()
}

type fromPrefetcher struct{}

func getLvl1Key(ctx context.Context, engine ServiceEngine,
	srcIA, dstIA addr.IA, proto drkey.Protocol, valTime time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	meta := drkey.Lvl1Meta{
		Validity: valTime,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		ProtoId:  proto,
	}
	pref_ctx := context.WithValue(ctx, fromPrefetcher{}, true)
	_, err := engine.GetLvl1Key(pref_ctx, meta)
	if err != nil {
		log.Error("Failed to prefetch the level 1 key", "remote AS", srcIA.String(),
			"protocol", proto, "error", err)
	}
}
