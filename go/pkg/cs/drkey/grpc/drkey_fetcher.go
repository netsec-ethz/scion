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
)

// DRKeyFetcher obtains Lvl1 DRKey from a remote CS.
type DRKeyFetcher struct {
	Dialer sc_grpc.Dialer
	Router snet.Router
}

var _ csdrkey.Fetcher = (*DRKeyFetcher)(nil)

// GetLvl1FromOtherCS queries a CS for a level 1 key.
func (f DRKeyFetcher) GetLvl1FromOtherCS(ctx context.Context,
	srcIA, dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error) {
	logger := log.FromCtx(ctx)

	logger.Info("[DRKey Fetcher] resolving server", "srcIA", srcIA.String())
	path, err := f.Router.Route(ctx, srcIA)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("retrieving paths", err)
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Path(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}

	// grpc.DialContext, using credentials +  remote addr.
	conn, err := f.Dialer.Dial(ctx, remote)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyLvl1ServiceClient(conn)
	lvl1req := ctrl.NewLvl1Req(dstIA, valTime)
	req, err := ctrl.Lvl1reqToProtoRequest(lvl1req)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing lvl1 request to protobuf", err)
	}

	// Use client to request lvl1 key, get Lvl1Rep
	rep, err := client.DRKeyLvl1(ctx, req)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("requesting level 1 key", err)
	}

	lvl1Key, err := ctrl.GetLvl1KeyFromReply(rep)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from reply", err)
	}

	return lvl1Key, nil
}
