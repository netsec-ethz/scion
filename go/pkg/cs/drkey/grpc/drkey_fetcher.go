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

	"github.com/golang/protobuf/ptypes"

	"github.com/scionproto/scion/go/lib/addr"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	csdrkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	sc_grpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
	"github.com/scionproto/scion/go/pkg/trust"
)

// DRKeyFetcher obtains Lvl1 DRKey from a remote CS.
type DRKeyFetcher struct {
	Dialer sc_grpc.Dialer
	Router trust.Router
}

var _ csdrkey.Fetcher = (*DRKeyFetcher)(nil)

// GetLvl1FromOtherCS queries a CS for a level 1 key.
func (f DRKeyFetcher) GetLvl1FromOtherCS(ctx context.Context,
	srcIA, dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error) {

	remote, err := f.Router.ChooseServer(ctx, dstIA.I)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("choosing server", err)
	}

	// grpc.DialContext, using credentials +  remote addr.
	conn, err := f.Dialer.Dial(ctx, remote)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyLvl1ServiceClient(conn)
	lvl1req := ctrl.NewLvl1Req(dstIA, valTime)
	req, err := lvl1reqToProtoRequest(lvl1req)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing lvl1 request to protobuf", err)
	}

	// Use client to request lvl1 key, get Lvl1Rep
	rep, err := client.DRKeyLvl1(ctx, req)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("requesting level 1 key", err)
	}

	lvl1Key, err := getLvl1KeyFromReply(rep)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from reply", err)
	}

	return lvl1Key, nil
}

func lvl1reqToProtoRequest(req ctrl.Lvl1Req) (*dkpb.DRKeyLvl1Request, error) {
	valTime, err := ptypes.TimestampProto(req.ValTime)
	if err != nil {
		return nil, err
	}
	timestamp, err := ptypes.TimestampProto(req.Timestamp)
	if err != nil {
		return nil, err
	}
	return &dkpb.DRKeyLvl1Request{
		Dst_IA:    uint64(req.DstIA.IAInt()),
		ValTime:   valTime,
		Timestamp: timestamp,
	}, nil
}

// getLvl1KeyFromReply decrypts and extracts the level 1 drkey from the reply.
func getLvl1KeyFromReply(rep *dkpb.DRKeyLvl1Response) (drkey.Lvl1Key, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}
	return drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			SrcIA: addr.IAInt(rep.Src_IA).IA(),
			DstIA: addr.IAInt(rep.Dst_IA).IA(),
			Epoch: epoch,
		},
		Key: drkey.DRKey(rep.Drkey),
	}, nil
}
