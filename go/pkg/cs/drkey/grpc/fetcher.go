// Copyright 2020 ETH Zurich
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

package grpc

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	csdrkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	sc_grpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

const (
	// defaultRPCDialTimeout is the timeout used for dialing the gRPC ClientConn.
	// This is shorter than the typical context deadline for the request.
	// Having a separate, more aggressive timeout for dialing allows to abort
	// quickly. This allows the surrounding infrastructure to retry quickly -- in
	// the case where this request goes over SCION/QUIC, retries are used to
	// route around broken paths.
	// This timeout needs to be long enough to allow for service address
	// resolution and the QUIC handshake to complete (two roundtrips).
	defaultRPCDialTimeout time.Duration = 2 * time.Second
)

var errNotReachable = serrors.New("remote not reachable")

// Fetcher obtains Lvl1 DRKey from a remote CS.
type Fetcher struct {
	Dialer     sc_grpc.Dialer
	Router     snet.Router
	MaxRetries int
}

var _ csdrkey.Fetcher = (*Fetcher)(nil)

// Lvl1 queries a CS for a level 1 key.
func (f Fetcher) Lvl1(ctx context.Context,
	meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	logger := log.FromCtx(ctx)

	req, err := drkey.Lvl1MetaToProtoRequest(meta)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing lvl1 request to protobuf", err)
	}

	var rep *dkpb.Lvl1Response
	for i := 0; i < f.MaxRetries; i++ {
		rep, err = f.getLvl1Key(ctx, meta.SrcIA, req)
		if errors.Is(err, errNotReachable) {
			logger.Debug("Lvl1 fetch failed", "try", i+1, "peer", meta.SrcIA, "err", err)
			return drkey.Lvl1Key{}, err
		}
		if err == nil {
			lvl1Key, err := drkey.GetLvl1KeyFromReply(meta, rep)
			if err != nil {
				return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from reply", err)
			}
			return lvl1Key, nil
		}
		logger.Debug("Lvl1 fetch failed", "try", i+1, "peer", meta.SrcIA, "err", err)
	}
	return drkey.Lvl1Key{}, serrors.New("Reached max retry attempts on fetching lvl1 key")
}

func (f Fetcher) getLvl1Key(ctx context.Context, srcIA addr.IA,
	req *dkpb.Lvl1Request) (*dkpb.Lvl1Response, error) {
	logger := log.FromCtx(ctx)

	logger.Info("Resolving server", "srcIA", srcIA.String())
	path, err := f.pathToDst(ctx, srcIA)
	if err != nil {
		return nil, err
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	dialCtx, cancelF := context.WithTimeout(ctx, defaultRPCDialTimeout)
	defer cancelF()
	conn, err := f.Dialer.Dial(dialCtx, remote)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyInterServiceClient(conn)
	rep, err := client.Lvl1(ctx, req)
	if err != nil {
		return nil, serrors.WrapStr("requesting level 1 key", err)
	}
	return rep, nil
}

func (f Fetcher) pathToDst(ctx context.Context, dst addr.IA) (snet.Path, error) {
	paths, err := f.Router.AllRoutes(ctx, dst)
	if err != nil {
		return nil, serrors.Wrap(errNotReachable, err)
	}
	if len(paths) == 0 {
		return nil, errNotReachable
	}
	path := paths[rand.Intn(len(paths))]
	return path, nil
}
