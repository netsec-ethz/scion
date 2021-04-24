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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	csdrkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	sc_grpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

type Lvl1KeyGetter interface {
	GetLvl1Key(ctx context.Context, srcIA addr.IA,
		req *dkpb.DRKeyLvl1Request) (*dkpb.DRKeyLvl1Response, error)
}

type Lvl1KeyFetcher struct {
	Dialer sc_grpc.Dialer
	Router snet.Router
}

var _ Lvl1KeyGetter = (*Lvl1KeyFetcher)(nil)

func (f Lvl1KeyFetcher) GetLvl1Key(ctx context.Context, srcIA addr.IA,
	req *dkpb.DRKeyLvl1Request) (*dkpb.DRKeyLvl1Response, error) {
	logger := log.FromCtx(ctx)

	logger.Info("Resolving server", "srcIA", srcIA.String())
	path, err := f.Router.Route(ctx, srcIA)
	if err != nil || path == nil {
		return nil, serrors.WrapStr("unable to find path to", err, "IA", srcIA)
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Path(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	conn, err := f.Dialer.Dial(ctx, remote)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyLvl1ServiceClient(conn)
	rep, err := client.DRKeyLvl1(ctx, req)
	if err != nil {
		return nil, serrors.WrapStr("requesting level 1 key", err)
	}
	return rep, nil
}

// DRKeyFetcher obtains Lvl1 DRKey from a remote CS.
type DRKeyFetcher struct {
	Getter Lvl1KeyGetter
}

var _ csdrkey.Fetcher = (*DRKeyFetcher)(nil)

// GetLvl1FromOtherCS queries a CS for a level 1 key.
func (f DRKeyFetcher) GetLvl1FromOtherCS(ctx context.Context,
	srcIA, dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error) {

	lvl1req := ctrl.NewLvl1Req(valTime)
	req, err := ctrl.Lvl1reqToProtoRequest(lvl1req)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing lvl1 request to protobuf", err)
	}

	rep, err := f.Getter.GetLvl1Key(ctx, srcIA, req)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}

	lvl1Key, err := ctrl.GetLvl1KeyFromReply(srcIA, dstIA, rep)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from reply", err)
	}

	return lvl1Key, nil
}
