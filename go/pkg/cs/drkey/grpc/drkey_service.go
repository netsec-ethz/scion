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
	"time"

	"github.com/golang/protobuf/ptypes"
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
	Store drkeystorage.ServiceStore
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
		logger.Error("[DRKey ServiceStore] Cannot retrieve peer from ctx")
		return nil, serrors.New("retrieving peer information from ctx")
	}
	parsedReq, err := requestToLvl1Req(req)
	if err != nil {
		logger.Error("[DRKey ServiceStore] Invalid DRKey Lvl1 request",
			"peer", peer, "err", err)
		return nil, err
	}

	// validating peer Subject.IA == req.dstIA
	if err = exchange.ValitadePeerWithCert(peer, parsedReq.DstIA); err != nil {
		logger.Error("[DRKey ServiceStore] Error validating requested dstIA with certicate",
			"err", err)
		return nil, serrors.WrapStr("validating requested dstIA", err)
	}

	logger.Debug("[DRKey ServiceStore] Received Lvl1 request",
		"lvl1_req", parsedReq, "peer", peer)
	lvl1Key, err := d.Store.DeriveLvl1(parsedReq.DstIA, parsedReq.ValTime)
	if err != nil {
		logger.Error("Error deriving level 1 key", "err", err)
		return nil, err
	}
	resp, err := keyToLvl1Resp(lvl1Key)
	if err != nil {
		logger.Error("Error parsing DRKey Lvl1 to protobuf resp", "err", err)
		return nil, err
	}
	return resp, nil
}

func requestToLvl1Req(req *dkpb.DRKeyLvl1Request) (ctrl.Lvl1Req, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return ctrl.Lvl1Req{}, err
	}
	timestamp, err := ptypes.Timestamp(req.Timestamp)
	if err != nil {
		return ctrl.Lvl1Req{}, err
	}

	return ctrl.Lvl1Req{
		DstIA:     addr.IAInt(req.Dst_IA).IA(),
		ValTime:   valTime,
		Timestamp: timestamp,
	}, nil
}

func keyToLvl1Resp(drkey drkey.Lvl1Key) (*dkpb.DRKeyLvl1Response, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, err
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, err
	}
	now, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, err
	}

	return &dkpb.DRKeyLvl1Response{
		Dst_IA:     uint64(drkey.DstIA.IAInt()),
		Src_IA:     uint64(drkey.SrcIA.IAInt()),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(drkey.Key),
		Timestamp:  now,
	}, nil
}

// DRKeyLvl2 handles a level 2 drkey request and returns a level 2 response.
func (d *DRKeyServer) DRKeyLvl2(ctx context.Context,
	req *dkpb.DRKeyLvl2Request) (*dkpb.DRKeyLvl2Response, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		logger.Error("[DRKey ServiceStore] Cannot retrieve peer from ctx")
		return nil, serrors.New("retrieving peer information from ctx")
	}

	parsedReq, err := requestToLvl2Req(req)
	if err != nil {
		logger.Error("[DRKey ServiceStore] Invalid DRKey Lvl2 request",
			"peer", peer, "err", err)
		return nil, err
	}
	if err := d.validateLvl2Req(parsedReq, peer.Addr); err != nil {
		log.Error("[DRKey ServiceStore] Error validating Lvl2 request",
			"err", err)
		return nil, err
	}
	logger.Debug("[DRKey ServiceStore] Received Lvl2 request",
		"lvl2_req", parsedReq, "peer", peer)

	srcIA := parsedReq.SrcIA
	dstIA := parsedReq.DstIA
	logger.Debug(" [DRKey ServiceStore] Received request",
		"Type", parsedReq.ReqType, "protocol", parsedReq.Protocol,
		"SrcIA", srcIA, "DstIA", dstIA)
	lvl1Meta := drkey.Lvl1Meta{
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	lvl1Key, err := d.Store.GetLvl1Key(ctx, lvl1Meta, parsedReq.ValTime)
	if err != nil {
		logger.Error("[DRKey ServiceStore] Error getting the level 1 key",
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
		logger.Error("[DRKey ServiceStore] Error deriving level 2 key",
			"err", err)
		return nil, err
	}

	resp, err := keyToLvl2Resp(lvl2Key)
	if err != nil {
		logger.Debug("[DRKey ServiceStore] Error parsing DRKey Lvl2 to protobuf resp",
			"err", err)
		return nil, err
	}
	return resp, nil
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
	switch drkey.Lvl2KeyType(req.ReqType) {
	case drkey.Host2Host:
		if localAddr.Equal(req.SrcHost.ToHostAddr()) {
			break
		}
		fallthrough
	case drkey.AS2Host:
		if localAddr.Equal(req.DstHost.ToHostAddr()) {
			break
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

func requestToLvl2Req(req *dkpb.DRKeyLvl2Request) (ctrl.Lvl2Req, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return ctrl.Lvl2Req{}, err
	}

	return ctrl.Lvl2Req{
		Protocol: req.Protocol,
		ReqType:  req.ReqType,
		ValTime:  valTime,
		SrcIA:    addr.IAInt(req.Src_IA).IA(),
		DstIA:    addr.IAInt(req.Dst_IA).IA(),
		SrcHost: ctrl.Host{
			Type: addr.HostAddrType(req.SrcHost.Type),
			Host: req.SrcHost.Host,
		},
		DstHost: ctrl.Host{
			Type: addr.HostAddrType(req.DstHost.Type),
			Host: req.DstHost.Host,
		},
		Misc: req.Misc,
	}, nil
}

func keyToLvl2Resp(drkey drkey.Lvl2Key) (*dkpb.DRKeyLvl2Response, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, err
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, err
	}
	now, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, err
	}

	return &dkpb.DRKeyLvl2Response{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(drkey.Key),
		Timestamp:  now,
	}, nil
}
