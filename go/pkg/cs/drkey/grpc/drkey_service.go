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

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"inet.af/netaddr"

	"github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	cs_drkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

// Server keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type Server struct {
	LocalIA addr.IA
	Engine  cs_drkey.ServiceEngine
	// AllowedSVHost is a set of Host,Protocol pairs that represents the allowed
	// protocols hosts can obtain secrets values for.
	AllowedSVHostProto map[config.HostProto]struct{}
}

var _ cppb.DRKeyInterServiceServer = &Server{}
var _ cppb.DRKeyIntraServiceServer = &Server{}

// Lvl1 handle a level 1 request and returns a level 1 response.
func (d *Server) Lvl1(ctx context.Context,
	req *dkpb.Lvl1Request) (*dkpb.Lvl1Response, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("Cannot retrieve peer information from ctx")
	}
	dstIA, err := extractIAFromPeer(peer)
	if err != nil {
		return nil, serrors.WrapStr("retrieving info from certficate", err)
	}

	lvl1Meta, err := getMeta(req.ProtocolId, req.ValTime, d.LocalIA, dstIA)
	if err != nil {
		return nil, serrors.WrapStr("Invalid DRKey Lvl1 request", err)
	}

	// validate requested ProtoID is specific
	if !lvl1Meta.ProtoId.IsPredefined() {
		return nil, serrors.New("The requested protocol id is not recognized",
			"protoID", lvl1Meta.ProtoId)
	}

	logger.Debug("[DRKey gRPC server] Received Lvl1 request",
		"lvl1_meta", lvl1Meta, "peer", peer.Addr.String(), "IA from cert", dstIA.String())

	lvl1Key, err := d.Engine.DeriveLvl1(lvl1Meta)
	if err != nil {
		logger.Error("Error deriving level 1 key", "err", err)
		return nil, err
	}
	resp, err := ctrl.KeyToLvl1Resp(lvl1Key)
	if err != nil {
		return nil, serrors.WrapStr("Error parsing DRKey Lvl1 to protobuf resp", err)
	}
	return resp, nil
}

func getMeta(protoId dkpb.Protocol, ts *timestamppb.Timestamp, srcIA, dstIA addr.IA) (drkey.Lvl1Meta, error) {
	valTime, err := ptypes.Timestamp(ts)
	if err != nil {
		return drkey.Lvl1Meta{}, serrors.WrapStr("invalid valTime from pb req", err)
	}
	return drkey.Lvl1Meta{
		Validity: valTime,
		ProtoId:  drkey.Protocol(protoId),
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}, nil
}

func extractIAFromPeer(peer *peer.Peer) (addr.IA, error) {
	if peer.AuthInfo == nil {
		return 0, serrors.New("no auth info", "peer", peer)
	}
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return 0, serrors.New("auth info is not of type TLS info",
			"peer", peer, "authType", peer.AuthInfo.AuthType())
	}
	chain := tlsInfo.State.PeerCertificates
	certIA, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return 0, serrors.WrapStr("extracting IA from peer cert", err)
	}
	return certIA, nil
}

func (d *Server) ASAS(ctx context.Context, req *dkpb.ASASRequest) (*dkpb.ASASResponse, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("Cannot retrieve peer information from ctx")
	}

	if d.LocalIA != addr.IA(req.SrcIa) && d.LocalIA != addr.IA(req.DstIa) {
		return nil, serrors.New("Local IA is not part of the request")
	}

	meta, err := getMeta(req.ProtocolId, req.ValTime, addr.IA(req.SrcIa), addr.IA(req.DstIa))
	if err != nil {
		return nil, serrors.WrapStr("parsing AS-AS request", err)
	}
	if err := d.validateAllowedHost(meta.ProtoId, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating AS-AS request", err)
	}

	lvl1Key, err := d.Engine.GetLvl1Key(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting AS-AS host key", err)
	}

	resp, err := ctrl.KeyToASASResp(lvl1Key)
	if err != nil {
		return nil, serrors.WrapStr("encoding AS-AS to Protobuf response", err)
	}
	return resp, nil
}

func (d *Server) ASHost(ctx context.Context,
	req *dkpb.ASHostRequest) (*dkpb.ASHostResponse, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("Cannot retrieve peer information from ctx")
	}

	meta, err := ctrl.RequestToASHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing DRKey AS-Host request", err)
	}
	if err := validateASHostReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating AS-Host request", err)
	}

	logger.Debug(" [DRKey gRPC server] Received AS-Host request",
		"protocol", meta.ProtoId,
		"SrcIA", meta.SrcIA, "DstIA", meta.DstIA)

	asHostKey, err := d.Engine.DeriveASHost(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving AS-Host request", err)
	}

	resp, err := ctrl.KeyToASHostResp(asHostKey)
	if err != nil {
		return nil, serrors.WrapStr("parsing AS-Host request", err)
	}
	return resp, nil
}

// validateASHostReq returns and error if the requesting host is different from the
// requested dst host. The source AS infraestructure nodes are not supposed to contact
// the local CS but to derive this key from the SV instead.
func validateASHostReq(meta drkey.ASHostMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}

	if !meta.DstIA.Equal(localIA) {
		return serrors.New("invalid request, req.dstIA != localIA",
			"req.dstIA", meta.DstIA, "localIA", localIA)
	}
	dstHost := addr.HostFromIPStr(meta.DstHost)
	if !hostAddr.Equal(dstHost) {
		return serrors.New("invalid request, dst_host != remote host",
			"dst_host", dstHost, "remote_host", hostAddr)
	}
	return nil
}

func (d *Server) HostAS(ctx context.Context,
	req *dkpb.HostASRequest) (*dkpb.HostASResponse, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		serrors.New("Cannot retrieve peer information from ctx")
	}

	meta, err := ctrl.RequestToHostASMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-AS request", err)
	}
	if err := validateHostASReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating Host-AS request", err)
	}
	logger.Debug(" [DRKey gRPC server] Received Host-AS request",
		"protocol", meta.ProtoId,
		"SrcIA", meta.SrcIA, "DstIA", meta.DstIA)
	key, err := d.Engine.DeriveHostAS(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving Host-AS request", err)
	}

	resp, err := ctrl.KeyToHostASResp(key)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-AS request", err)
	}
	return resp, nil
}

// validateASHostReq returns and error if the requesting host is different from the
// requested src host. The dst AS infraestructure nodes are not supposed to contact
// the local CS but to derive this key from the SV instead.
func validateHostASReq(meta drkey.HostASMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}

	if !meta.SrcIA.Equal(localIA) {
		return serrors.New("invalid request, req.SrcIA != localIA",
			"req.SrcIA", meta.SrcIA, "localIA", localIA)
	}
	srcHost := addr.HostFromIPStr(meta.SrcHost)
	if !hostAddr.Equal(srcHost) {
		return serrors.New("invalid request, src_host != remote host",
			"src_host", srcHost, "remote_host", hostAddr)
	}
	return nil
}

func (d *Server) HostHost(ctx context.Context,
	req *dkpb.HostHostRequest) (*dkpb.HostHostResponse, error) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext(ctx)
	if !ok {
		serrors.New("Cannot retrieve peer information from ctx")
	}

	meta, err := ctrl.RequestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-Host request", err)
	}
	if err := validateHostHostReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating Host-Host request", err)
	}

	logger.Debug(" [DRKey gRPC server] Received Host-Host request",
		"protocol", meta.ProtoId,
		"SrcIA", meta.SrcIA, "DstIA", meta.DstIA)

	key, err := d.Engine.DeriveHostHost(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving Host-Host request", err)
	}

	resp, err := ctrl.KeyToHostHostResp(key)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-Host request", err)
	}
	return resp, nil
}

// validateHostHostReq returns and error if the requesting host is different from the
// requested src host or the dst host.
func validateHostHostReq(meta drkey.HostHostMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}

	if meta.SrcIA.Equal(localIA) {
		srcHost := addr.HostFromIPStr(meta.SrcHost)
		if !hostAddr.Equal(srcHost) {
			return serrors.New("invalid request, src_host != remote host",
				"src_host", srcHost, "remote_host", hostAddr)
		}
		return nil
	}

	if meta.DstIA.Equal(localIA) {
		dstHost := addr.HostFromIPStr(meta.DstHost)
		if !hostAddr.Equal(dstHost) {
			return serrors.New("invalid request, dst_host != remote host",
				"dst_host", dstHost, "remote_host", hostAddr)
		}
		return nil
	}
	return serrors.New("invalid request, localIA not found in request",
		"localIA", localIA, "srcIA", meta.SrcIA, "dstIA", meta.DstIA)
}

func hostAddrFromPeer(peerAddr net.Addr) (addr.HostAddr, error) {
	tcpAddr, ok := peerAddr.(*net.TCPAddr)
	if !ok {
		return nil, serrors.New("invalid peer address type, expected *net.TCPAddr",
			"peer", peerAddr, "type", common.TypeOf(peerAddr))
	}
	return addr.HostFromIP(tcpAddr.IP), nil
}

// SV handles a SV request and returns a SV response.
func (d *Server) SV(ctx context.Context,
	req *dkpb.SVRequest) (*dkpb.SVResponse, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		serrors.New("Cannot retrieve peer information from ctx")
	}

	meta, err := ctrl.SVRequestToMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-Host request", err)
	}
	if err := d.validateAllowedHost(meta.ProtoId, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating SV request", err)
	}
	sv, err := d.Engine.GetSecretValue(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting SV from persistence", err)
	}
	resp, err := ctrl.SVtoProtoResp(sv)
	if err != nil {
		return nil, serrors.WrapStr("encoding SV to Protobuf response", err)
	}
	return resp, nil
}

// validateSVReq checks that the requester is authorized to receive a SV
func (d *Server) validateAllowedHost(protoId drkey.Protocol, peerAddr net.Addr) error {
	tcpAddr, ok := peerAddr.(*net.TCPAddr)
	if !ok {
		return serrors.New("invalid peer address type, expected *net.TCPAddr",
			"peer", peerAddr, "type", common.TypeOf(peerAddr))
	}
	localAddr, ok := netaddr.FromStdIP(tcpAddr.IP)
	if !ok {
		return serrors.New("unable to parse IP", "addr", tcpAddr.IP.String())
	}
	hostProto := config.HostProto{
		Host:  localAddr,
		Proto: protoId,
	}

	_, foundSet := d.AllowedSVHostProto[hostProto]
	if foundSet {
		log.Debug("Authorized delegated secret",
			"protocol", protoId.String(),
			"requester address", localAddr.String(),
		)
		return nil
	}
	return serrors.New("endhost not allowed for DRKey request",
		"protocol", protoId.String(),
		"requester address", localAddr.String(),
	)
}
