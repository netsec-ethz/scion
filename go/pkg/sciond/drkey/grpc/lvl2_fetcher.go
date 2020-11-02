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
	"github.com/scionproto/scion/go/lib/serrors"
	sc_grpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/proto/daemon"
	sd_pb "github.com/scionproto/scion/go/pkg/proto/daemon"
	sd_drkey "github.com/scionproto/scion/go/pkg/sciond/drkey"
	"github.com/scionproto/scion/go/pkg/trust"
)

// DRKeyFetcher obtains Lvl2 DRKey from the local CS.
type DRKeyFetcher struct {
	Dialer sc_grpc.Dialer
	Router trust.Router
}

var _ sd_drkey.Fetcher = (*DRKeyFetcher)(nil)

// GetDRKeyLvl2 fetches the Lvl2Key corresponding to the metadata by requesting
// the CS.
func (f DRKeyFetcher) GetDRKeyLvl2(ctx context.Context, lvl2meta drkey.Lvl2Meta,
	dstIA addr.IA, valTime time.Time) (drkey.Lvl2Key, error) {

	csServer, err := f.Router.ChooseServer(ctx, dstIA.I)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.WrapStr("choosing server", err)
	}

	// grpc.DialContext, using credentials +  remote addr.
	conn, err := f.Dialer.Dial(ctx, csServer)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := daemon.NewDaemonServiceClient(conn)
	lvl2req := ctrl.NewLvl2ReqFromMeta(lvl2meta, valTime)
	req, err := lvl2reqToProtoRequest(lvl2req)
	if err != nil {
		return drkey.Lvl2Key{},
			serrors.WrapStr("parsing lvl2 request to protobuf", err)
	}
	rep, err := client.DRKeyLvl2(ctx, req)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.WrapStr("requesting level 2 key", err)
	}

	lvl2Key, err := getLvl2KeyFromReply(rep, lvl2meta)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.WrapStr("obtaining level 2 key from reply", err)
	}

	return lvl2Key, nil
}

func lvl2reqToProtoRequest(req ctrl.Lvl2Req) (*sd_pb.DRKeyLvl2Request, error) {
	baseReq, err := ctrl.Lvl2reqToProtoRequest(req)
	if err != nil {
		return nil, err
	}
	return &sd_pb.DRKeyLvl2Request{
		BaseReq: baseReq,
	}, nil
}

// getLvl2KeyFromReply decrypts and extracts the level 1 drkey from the reply.
func getLvl2KeyFromReply(rep *sd_pb.DRKeyLvl2Response, meta drkey.Lvl2Meta) (drkey.Lvl2Key, error) {
	return ctrl.GetLvl2KeyFromReply(rep.BaseRep, meta)
}
