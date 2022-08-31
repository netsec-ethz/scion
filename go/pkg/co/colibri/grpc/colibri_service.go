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

package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/peer"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type ColibriService struct {
	Store reservationstorage.Store
}

var _ colpb.ColibriServiceServer = (*ColibriService)(nil)

func (s *ColibriService) SegmentSetup(ctx context.Context, msg *colpb.SegmentSetupRequest) (
	*colpb.SegmentSetupResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.SetupReq(msg, path)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		// should send a message?
		return nil, err
	}
	res, err := s.Store.AdmitSegmentReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		// should send a message?
		return nil, err
	}
	pbRes := translate.PBufSetupResponse(res)
	return pbRes, nil
}

func (s *ColibriService) ConfirmSegmentIndex(ctx context.Context,
	msg *colpb.ConfirmSegmentIndexRequest) (*colpb.ConfirmSegmentIndexResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.Request(msg.Base)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		return nil, err
	}
	res, err := s.Store.ConfirmSegmentReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		return nil, err
	}
	pbRes := translate.PBufResponse(res)

	return &colpb.ConfirmSegmentIndexResponse{
		Base: pbRes,
	}, nil
}

func (s *ColibriService) ActivateSegmentIndex(ctx context.Context,
	msg *colpb.ActivateSegmentIndexRequest) (*colpb.ActivateSegmentIndexResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.Request(msg.Base)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		return nil, err
	}
	res, err := s.Store.ActivateSegmentReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		return nil, err
	}
	pbRes := translate.PBufResponse(res)

	return &colpb.ActivateSegmentIndexResponse{
		Base: pbRes,
	}, nil
}

func (s *ColibriService) TeardownSegment(ctx context.Context, msg *colpb.TeardownSegmentRequest) (
	*colpb.TeardownSegmentResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.Request(msg.Base)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		return nil, err
	}
	res, err := s.Store.TearDownSegmentReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		return nil, err
	}
	pbRes := translate.PBufResponse(res)

	return &colpb.TeardownSegmentResponse{
		Base: pbRes,
	}, nil
}

func (s *ColibriService) CleanupSegmentIndex(ctx context.Context,
	msg *colpb.CleanupSegmentIndexRequest) (*colpb.CleanupSegmentIndexResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.Request(msg.Base)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		return nil, err
	}
	res, err := s.Store.CleanupSegmentReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		return nil, err
	}
	pbRes := translate.PBufResponse(res)

	return &colpb.CleanupSegmentIndexResponse{
		Base: pbRes,
	}, nil
}

func (s *ColibriService) ListReservations(ctx context.Context, msg *colpb.ListReservationsRequest) (
	*colpb.ListReservationsResponse, error) {

	dstIA := addr.IA(msg.DstIa)
	looks, err := s.Store.ListReservations(ctx, dstIA, reservation.PathType(msg.PathType))
	if err != nil {
		log.Info("error colibri store while listing rsvs", "err", err)
		return &colpb.ListReservationsResponse{
			ErrorMessage: err.Error(),
		}, nil
	}
	return translate.PBufListResponse(looks), nil
}

func (s *ColibriService) E2ESetup(ctx context.Context, msg *colpb.E2ESetupRequest) (
	*colpb.E2ESetupResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	msg.Params.CurrentStep++
	req, err := translate.E2ESetupRequest(msg)
	if err != nil {
		log.Info("error translating e2e setup", "err", err)
		return nil, serrors.WrapStr("translating e2e setup", err)
	}
	res, err := s.Store.AdmitE2EReservation(ctx, req, path)
	if err != nil {
		log.Info("error admitting e2e", "err", err)
		return nil, err
	}
	return translate.PBufE2ESetupResponse(res), nil
}

func (s *ColibriService) CleanupE2EIndex(ctx context.Context, msg *colpb.CleanupE2EIndexRequest) (
	*colpb.CleanupE2EIndexResponse, error) {

	path, err := extractPathIAFromCtx(ctx)
	if err != nil {
		log.Info("error setup segment", "err", err)
		return nil, err
	}
	req, err := translate.E2ERequest(msg.Base)
	if err != nil {
		log.Info("error unmarshalling", "err", err)
		return nil, err
	}
	res, err := s.Store.CleanupE2EReservation(ctx, req, path)
	if err != nil {
		log.Info("error colibri store returned an error", "err", err)
		return nil, err
	}
	pbRes := translate.PBufResponse(res)

	return &colpb.CleanupE2EIndexResponse{
		Base: pbRes,
	}, nil
}

func (s *ColibriService) ListStitchables(ctx context.Context, msg *colpb.ListStitchablesRequest) (
	*colpb.ListStitchablesResponse, error) {

	if _, err := checkLocalCaller(ctx); err != nil {
		return nil, err
	}

	dstIA := addr.IA(msg.DstIa)
	stitchables, err := s.Store.ListStitchableSegments(ctx, dstIA)
	if err != nil {
		log.Info("error colibri store while listing stitchables", "err", err)
		return &colpb.ListStitchablesResponse{
			ErrorMessage: err.Error(),
		}, nil
	}
	return translate.PBufStitchableResponse(stitchables), nil
}

// SetupReservation serves the intra AS clients, setting up or renewing an E2E reservation.
func (s *ColibriService) SetupReservation(ctx context.Context, msg *colpb.SetupReservationRequest) (
	*colpb.SetupReservationResponse, error) {

	_, err := checkLocalCaller(ctx)
	if err != nil {
		return nil, err
	}

	// TODO(juagargi) validate the incoming request
	// build a valid E2E setup request now and query the store with it
	pbReq := &colpb.E2ESetupRequest{
		Base: &colpb.E2ERequest{
			Base: &colpb.Request{
				Id:             msg.Id,
				Index:          msg.Index,
				Timestamp:      msg.Timestamp,
				Authenticators: &colpb.Authenticators{},
			},
			SrcHost: msg.SrcHost,
			DstHost: msg.DstHost,
		},
		RequestedBw: msg.RequestedBw,
		Params: &colpb.E2ESetupRequest_PathParams{
			Segments:       msg.Segments,
			CurrentSegment: 0,
			Steps:          msg.PathSteps,
			CurrentStep:    0,
		},
		Allocationtrail: nil,
	}
	pbReq.Base.Base.Authenticators.Macs = msg.Authenticators.Macs
	req, err := translate.E2ESetupRequest(pbReq)
	if err != nil {
		log.Info("error translating initial E2E setup from daemon to service", "err", err)
		return nil, err
	}

	res, err := s.Store.AdmitE2EReservation(ctx, req, empty.Path{})
	if err != nil {
		log.Info("error colibri store setting up an e2e reservation", "err", err)
		var trail []uint32
		var failedStep uint32
		if failure, ok := res.(*e2e.SetupResponseFailure); ok {
			trail = make([]uint32, len(failure.AllocTrail))
			for i, b := range failure.AllocTrail {
				trail[i] = uint32(b)
			}
			failedStep = uint32(failure.FailedStep)
		}
		// TODO(juagargi) unify criteria in all RPCs: when error, return error or failure message?
		return &colpb.SetupReservationResponse{
			// Authenticators: &colpb.Authenticators{Macs: fai},
			Failure: &colpb.SetupReservationResponse_Failure{
				ErrorMessage: err.Error(),
				FailedStep:   failedStep,
				AllocTrail:   trail,
			},
		}, nil
	}
	pbMsg := &colpb.SetupReservationResponse{
		Authenticators: &colpb.Authenticators{},
	}
	switch res := res.(type) {
	case *e2e.SetupResponseFailure:
		pbMsg.Authenticators.Macs = res.Authenticators
		trail := make([]uint32, len(res.AllocTrail))
		for i, b := range res.AllocTrail {
			trail[i] = uint32(b)
		}
		pbMsg.Failure = &colpb.SetupReservationResponse_Failure{
			ErrorMessage: res.Message,
			FailedStep:   uint32(res.FailedStep),
			AllocTrail:   trail,
		}
	case *e2e.SetupResponseSuccess:
		pbMsg.Authenticators.Macs = res.Authenticators
		token, err := reservation.TokenFromRaw(res.Token)
		if err != nil {
			return nil, serrors.WrapStr("decoding token in colibri service", err)
		}
		path := e2e.DeriveColibriPath(&req.ID, token)
		egressId := ""
		if len(path.HopFields) > 0 {
			egressId = fmt.Sprintf("%d", path.HopFields[0].EgressId)
		}
		rawPath := make([]byte, path.Len())
		err = path.SerializeTo(rawPath)
		if err != nil {
			return nil, serrors.WrapStr("serializing a colibri path in colibri service", err)
		}
		// nexthop holds the interface id until the daemon resolves it with the topology
		pbMsg.Success = &colpb.SetupReservationResponse_Success{
			RawPath: rawPath,
			NextHop: egressId,
		}
	}
	return pbMsg, nil
}

// CleanupReservation serves the intra AS clients, cleaning an E2E reservation.
func (s *ColibriService) CleanupReservation(ctx context.Context,
	msg *colpb.CleanupReservationRequest) (*colpb.CleanupReservationResponse, error) {

	if _, err := checkLocalCaller(ctx); err != nil {
		return nil, err
	}

	req := &e2e.Request{
		Request: *base.NewRequest(time.Now(), translate.ID(msg.Base.Id),
			reservation.IndexNumber(msg.Base.Index), len(msg.Base.Authenticators.Macs)),
		SrcHost: msg.SrcHost,
		DstHost: msg.DstHost,
	}
	req.Authenticators = msg.Base.Authenticators.Macs

	res, err := s.Store.CleanupE2EReservation(ctx, req, empty.Path{})
	if err != nil {
		var failedStep uint32
		if failure, ok := res.(*base.ResponseFailure); ok {
			failedStep = uint32(failure.FailedStep)
		}
		return &colpb.CleanupReservationResponse{
			Failure: &colpb.CleanupReservationResponse_Failure{
				ErrorMessage: err.Error(),
				FailedStep:   uint32(failedStep),
			},
		}, nil
	}
	return &colpb.CleanupReservationResponse{}, nil
}

func (s *ColibriService) AddAdmissionEntry(ctx context.Context,
	req *colpb.AddAdmissionEntryRequest) (*colpb.AddAdmissionEntryResponse, error) {

	clientAddr, err := checkLocalCaller(ctx)
	if err != nil {
		return nil, err
	}
	// TODO(juagargi)
	// because we can't guarantee that the IP the client requested is reachable from this
	// service, checking that the connection from the endhost to this service uses the same
	// IP is wrong.
	// A new design for this check must be created and implemented. For now, the check is
	// completely disabled (commented code below).
	// if len(req.DstHost) > 0 {
	// 	// check that we have the same IP address in the DstHost field and the TCP connection
	// 	if !bytes.Equal(req.DstHost, clientAddr.IP) {
	// 		return nil, serrors.New("IP address in request not the same as connnection",
	// 			"req", net.IP(req.DstHost).String(), "conn", clientAddr.IP.String())
	// 	}
	// }
	if len(req.DstHost) == 0 {
		req.DstHost = clientAddr.IP
	}
	entry := &colibri.AdmissionEntry{
		DstHost:         req.DstHost,
		ValidUntil:      util.SecsToTime(req.ValidUntil),
		RegexpIA:        req.RegexpIa,
		RegexpHost:      req.RegexpHost,
		AcceptAdmission: req.Accept,
	}
	validUntil, err := s.Store.AddAdmissionEntry(ctx, entry)
	return &colpb.AddAdmissionEntryResponse{
		ValidUntil: util.TimeToSecs(validUntil),
	}, err
}

// checkLocalCaller prevents the service from doing anything if the caller is not from the local AS.
// We do it by checking the peer. We could instantiate the local ColibriService differently.
func checkLocalCaller(ctx context.Context) (*net.TCPAddr, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, serrors.New("no peer found")
	}
	tcpaddr, ok := p.Addr.(*net.TCPAddr)
	if !ok || tcpaddr == nil {
		return nil, serrors.New("no valid local tcp address found", "addr", p.Addr,
			"type", common.TypeOf(p.Addr))
	}
	return tcpaddr, nil
}

// extractPathIAFromCtx returns the forwarding path that was used to reach the service.
func extractPathIAFromCtx(ctx context.Context) (slayerspath.Path, error) {
	gPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("peer must exist")
	}
	logger := log.FromCtx(ctx)

	peer, ok := gPeer.Addr.(*snet.UDPAddr)
	if !ok {
		logger.Debug("peer must be *snet.UDPAddr", "actual", fmt.Sprintf("%T", gPeer))
		return nil, serrors.New(
			"peer must be *snet.UDPAddr",
			"actual",
			fmt.Sprintf("%T", gPeer),
		)
	}

	path, err := base.PathFromDataplanePath(peer.Path)
	if err != nil || path == nil {
		return nil, serrors.WrapStr("decoding path information", err)
	}

	// The path extracted from the remote address is actually the replyPath (i.e.,
	// the path already reversed to answer back to the remote);
	// e.g. AS_{n-1}->...-> AS_Local -> AS_i -> ... AS_0.
	// However, here we want to extract the forwarding path. We reverse the
	// path again to recover forwarding direction path;
	// e.g. AS_0 -> ... -> AS_i -> AS_Local -> ... -> AS_{n_1}
	fwdPath, err := copyFrom(path).Reverse()
	if err != nil {
		return nil, serrors.WrapStr("reversing path", err)
	}

	return fwdPath, nil
}

func copyFrom(p slayerspath.Path) slayerspath.Path {
	var rp slayerspath.Path
	if p != nil {
		var err error
		buff := make([]byte, p.Len())
		if err = p.SerializeTo(buff); err != nil {
			panic(fmt.Sprintf("cannot copy path, SerializeTo failed: %s", err))
		}
		rp, err = slayerspath.NewPath(p.Type())
		if err != nil {
			panic(err)
		}
		if err = rp.DecodeFromBytes(buff); err != nil {
			panic(fmt.Sprintf("cannot copy path, DecodeFromBytes failed: %s", err))
		}
	}
	return rp
}
