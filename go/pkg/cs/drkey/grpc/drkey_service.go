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
	"net"

	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/exchange"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

// DRKeyServer keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type DRKeyServer struct {
	LocalIA addr.IA
	Store   drkeystorage.ServiceStore
	// AllowedDSs is a set of protocols per IP address (in 16 byte form). Represents the allowed
	// protocols hosts can obtain delegation secrets for.
	AllowedDSs map[[16]byte]map[string]struct{}
}

var _ cppb.DRKeyLvl1ServiceServer = &DRKeyServer{}
var _ cppb.DRKeyLvl2ServiceServer = &DRKeyServer{}

// DRKeyLvl1 handle a level 1 request and returns a level 1 response.
func (d *DRKeyServer) DRKeyLvl1(ctx context.Context,
	req *dkpb.DRKeyLvl1Request) (*dkpb.DRKeyLvl1Response, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		logger.Error("[DRKey gRPC server] Cannot retrieve peer from ctx")
		return nil, serrors.New("retrieving peer information from ctx")
	}
	parsedReq, err := ctrl.RequestToLvl1Req(req)
	if err != nil {
		logger.Error("[DRKey gRPC server] Invalid DRKey Lvl1 request",
			"peer", peer, "err", err)
		return nil, err
	}

	dstIA, err := exchange.ExtractIAFromPeer(peer)
	if err != nil {
		logger.Error("[DRKey gRPC server] Error retrieving auth info from certicate",
			"err", err)
		return nil, serrors.WrapStr("retrieving info from certficate", err)
	}

	logger.Debug("[DRKey gRPC server] Received Lvl1 request",
		"lvl1_req", parsedReq, "peer", peer.Addr.String(), "IA from cert", dstIA.String())
	lvl1Key, err := d.Store.DeriveLvl1(dstIA, parsedReq.ValTime)
	if err != nil {
		logger.Error("Error deriving level 1 key", "err", err)
		return nil, err
	}
	resp, err := ctrl.KeyToLvl1Resp(lvl1Key)
	if err != nil {
		logger.Error("[DRKey gRPC server] Error parsing DRKey Lvl1 to protobuf resp", "err", err)
		return nil, err
	}
	return resp, nil
}

// DRKeyLvl2 handles a level 2 drkey request and returns a level 2 response.
func (d *DRKeyServer) DRKeyLvl2(ctx context.Context,
	req *cppb.DRKeyLvl2Request) (*cppb.DRKeyLvl2Response, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		logger.Error("[DRKey gRPC server] Cannot retrieve peer from ctx")
		return nil, serrors.New("retrieving peer information from ctx")
	}

	parsedReq, err := requestToLvl2Req(req)
	if err != nil {
		logger.Error("[DRKey gRPC server] Invalid DRKey Lvl2 request",
			"peer", peer, "err", err)
		return nil, err
	}
	if err := d.validateLvl2Req(parsedReq, peer.Addr); err != nil {
		log.Error("[DRKey gRPC server] Error validating Lvl2 request",
			"err", err)
		return nil, err
	}

	srcIA := parsedReq.SrcIA
	dstIA := parsedReq.DstIA
	logger.Debug(" [DRKey gRPC server] Received lvl2 request",
		"Type", parsedReq.ReqType, "protocol", parsedReq.Protocol,
		"SrcIA", srcIA, "DstIA", dstIA)
	lvl1Meta := drkey.Lvl1Meta{
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	lvl1Key, err := d.Store.GetLvl1Key(ctx, lvl1Meta, parsedReq.ValTime)
	if err != nil {
		logger.Error("[DRKey gRPC server] Error getting the level 1 key",
			"err", err)
		return nil, err
	}
	lvl2Meta := drkey.Lvl2Meta{
		Epoch:    lvl1Key.Epoch,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		KeyType:  drkey.Lvl2KeyType(parsedReq.ReqType),
		Protocol: parsedReq.Protocol,
		SrcHost:  parsedReq.SrcHost.ToHostAddr(),
		DstHost:  parsedReq.DstHost.ToHostAddr(),
	}

	lvl2Key, err := deriveLvl2(lvl2Meta, lvl1Key)
	if err != nil {
		logger.Error("[DRKey gRPC server] Error deriving level 2 key",
			"err", err)
		return nil, err
	}

	resp, err := keyToLvl2Resp(lvl2Key)
	if err != nil {
		logger.Debug("[DRKey gRPC server] Error parsing DRKey Lvl2 to protobuf resp",
			"err", err)
		return nil, err
	}
	return resp, nil
}

func requestToLvl2Req(req *cppb.DRKeyLvl2Request) (ctrl.Lvl2Req, error) {
	return ctrl.RequestToLvl2Req(req.BaseReq)
}

func keyToLvl2Resp(drkey drkey.Lvl2Key) (*cppb.DRKeyLvl2Response, error) {
	baseRep, err := ctrl.KeyToLvl2Resp(drkey)
	if err != nil {
		return nil, err
	}
	return &cppb.DRKeyLvl2Response{
		BaseRep: baseRep,
	}, nil
}

// deriveLvl2 will derive the level 2 key specified by the meta data and the level 1 key.
func deriveLvl2(meta drkey.Lvl2Meta, lvl1Key drkey.Lvl1Key) (
	drkey.Lvl2Key, error) {

	der, found := protocol.KnownDerivations[meta.Protocol]
	if !found {
		return drkey.Lvl2Key{}, serrors.New("no derivation found for protocol",
			"protocol", meta.Protocol)
	}
	return der.DeriveLvl2(meta, lvl1Key)
}

// validateLvl2Req checks that the requester is in the destination of the key
// if AS2Host or host2host, and checks that the requester is authorized as to
// get a DS if AS2AS (AS2AS == DS).
func (d *DRKeyServer) validateLvl2Req(req ctrl.Lvl2Req, peerAddr net.Addr) error {
	tcpAddr, ok := peerAddr.(*net.TCPAddr)
	if !ok {
		return serrors.New("invalid peer address type, expected *net.TCPAddr",
			"peer", peerAddr, "type", common.TypeOf(peerAddr))
	}
	localAddr := addr.HostFromIP(tcpAddr.IP)

	if req.SrcIA != d.LocalIA && req.DstIA != d.LocalIA {
		return serrors.New("invalid request, localIA not found in request",
			"localIA", d.LocalIA, "srcIA", req.SrcIA, "dstIA", req.DstIA)
	}

	switch drkey.Lvl2KeyType(req.ReqType) {
	case drkey.Host2Host:
		if req.SrcIA == d.LocalIA {
			if localAddr.Equal(req.SrcHost.ToHostAddr()) {
				break
			}
		}
		fallthrough
	case drkey.AS2Host:
		if req.DstIA == d.LocalIA {
			if localAddr.Equal(req.DstHost.ToHostAddr()) {
				break
			}
		}
		fallthrough
	case drkey.AS2AS:
		// check in the allowed endhosts list
		var rawIP [16]byte
		copy(rawIP[:], localAddr.IP().To16())
		protocolSet, foundSet := d.AllowedDSs[rawIP]
		if foundSet {
			if _, found := protocolSet[req.Protocol]; found {
				log.Debug("Authorized delegated secret",
					"reqType", req.ReqType,
					"requester address", localAddr,
					"srcHost", req.SrcHost.ToHostAddr().String(),
					"dstHost", req.DstHost.ToHostAddr().String(),
				)
				return nil
			}
		}
		return serrors.New("endhost not allowed for DRKey request",
			"reqType", req.ReqType,
			"endhost address", localAddr,
			"srcHost", req.SrcHost.ToHostAddr().String(),
			"dstHost", req.DstHost.ToHostAddr().String(),
		)
	default:
		return serrors.New("unknown request type", "reqType", req.ReqType)
	}
	return nil
}
