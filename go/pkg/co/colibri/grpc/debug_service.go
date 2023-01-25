// Copyright 2022 ETH Zurich
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
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/coliquic"
	libcol "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/log"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

const newIndexMinDuration = 20 * time.Minute

type debugService struct {
	now      func() time.Time
	DB       backend.DB
	Operator *coliquic.ServiceClientOperator
	Topo     *topology.Loader
	Store    reservationstorage.Store
}

var _ colpb.ColibriDebugCommandsServiceServer = (*debugService)(nil)
var _ colpb.ColibriDebugServiceServer = (*debugService)(nil)

func NewDebugService(db backend.DB, operator *coliquic.ServiceClientOperator,
	topo *topology.Loader, store reservationstorage.Store) *debugService {
	return &debugService{
		now:      time.Now,
		DB:       db,
		Operator: operator,
		Topo:     topo,
		Store:    store,
	}
}

func (s *debugService) CmdTraceroute(ctx context.Context, req *colpb.CmdTracerouteRequest,
) (*colpb.CmdTracerouteResponse, error) {

	localIA := s.Topo.IA()
	errF := func(err error) (*colpb.CmdTracerouteResponse, error) {
		return &colpb.CmdTracerouteResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}
	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}
	log.Debug("deleteme",
		"path_type", rsv.PathType,
		"current_step", rsv.CurrentStep,
		"steps", rsv.Steps,
	)
	// fail if ¬( 0 OR (down AND last) ) = ¬0 AND ¬(down AND last) ¡ ¬0 AND (¬down OR ¬last)
	if (rsv.CurrentStep != 0) &&
		(rsv.PathType != libcol.DownPath || rsv.CurrentStep != len(rsv.Steps)-1) {

		return errF(status.Errorf(codes.Internal,
			"reservation does not start here. Src IA: %s, type: %s, this AS is at step %d",
			rsv.Steps.SrcIA(), rsv.PathType, rsv.CurrentStep))
	}

	if rsv.PathType == libcol.DownPath && rsv.CurrentStep == len(rsv.Steps)-1 {
		// At the end of a down path segment: means we want to walk the segment in reverse.
		req.DownDirection = true
	}

	// deleteme: all reservations must now contain a non nil colibri path in the direction of the traffic
	if rsv.TransportPath != nil {
		log.Debug("deleteme raw colibri path",
			"transport", rsv.TransportPath,
			"serialized", hex.EncodeToString(rsv.TransportPath.Raw),
		)
	}
	if rsv.TransportPath.Src == nil || rsv.TransportPath.Dst == nil {
		// this should be an assertion instead of a check
		return errF(status.Errorf(codes.Internal,
			"reservation transport with empty SRC or DST: %s", rsv.TransportPath.String()))
	}

	res, err := s.Traceroute(ctx, (*colpb.TracerouteRequest)(req))
	return (*colpb.CmdTracerouteResponse)(res), err
}

func (s *debugService) CmdIndexList(ctx context.Context, req *colpb.CmdIndexListRequest,
) (*colpb.CmdIndexListResponse, error) {
	localIA := s.Topo.IA()
	errF := func(err error) (*colpb.CmdIndexListResponse, error) {
		return &colpb.CmdIndexListResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}

	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}

	res := &colpb.CmdIndexListResponse{}
	for _, idx := range rsv.Indices {
		in := &colpb.CmdIndexListResponse_Index{
			Idx:        uint32(idx.Idx),
			State:      uint32(idx.State),
			Expiration: util.TimeToSecs(idx.Expiration),
			MinBW:      uint32(idx.MinBW),
			MaxBW:      uint32(idx.MaxBW),
			AllocBW:    uint32(idx.AllocBW),
		}
		res.Indices = append(res.Indices, in)
	}
	return res, nil
}

func (s *debugService) CmdIndexNew(ctx context.Context, req *colpb.CmdIndexNewRequest,
) (*colpb.CmdIndexNewResponse, error) {

	localIA := s.Topo.IA()
	errF := func(err error) (*colpb.CmdIndexNewResponse, error) {
		return &colpb.CmdIndexNewResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}

	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}

	// find out current values, or use defaults
	var min, max libcol.BWCls

	idx := rsv.ActiveIndex()
	switch {
	case idx == nil && len(rsv.Indices) > 0:
		idx = &rsv.Indices[0]
		fallthrough
	case idx != nil:
		min, max = idx.MinBW, idx.MaxBW
	default:
		min, max = 2, 2
	}

	// prepare renewal request and initiate via store
	now := s.now()
	renewReq := &segment.SetupReq{
		Request: *base.NewRequest(now, translate.ID(req.Id), rsv.NextIndexToRenew(),
			len(rsv.Steps)),
		ExpirationTime: now.Add(newIndexMinDuration),
		PathType:       rsv.PathType,
		MinBW:          min,
		MaxBW:          max,
		SplitCls:       rsv.TrafficSplit,
		PathProps:      rsv.PathEndProps,
		AllocTrail:     libcol.AllocationBeads{},
		Steps:          rsv.Steps.Copy(),
		CurrentStep:    rsv.CurrentStep,
		TransportPath:  rsv.TransportPath,
		Reservation:    rsv,
	}
	err = s.Store.InitSegmentReservation(ctx, renewReq)
	if err != nil {
		return errF(err)
	}
	// reload the reservation
	rsv = renewReq.Reservation

	// confirm index
	if err := rsv.SetIndexConfirmed(renewReq.Index); err != nil {
		return errF(err)
	}
	confirmReq := base.NewRequest(s.now(), &renewReq.ID, renewReq.Index, len(renewReq.Steps))
	steps := renewReq.Steps
	if renewReq.PathType == libcol.DownPath {
		steps = steps.Reverse()
	}
	res, err := s.Store.InitConfirmSegmentReservation(ctx, confirmReq, steps,
		renewReq.TransportPath)
	if err != nil {
		return errF(status.Errorf(codes.Internal,
			"confirming index: %v", err))
	}
	if !res.Success() {
		return errF(status.Errorf(codes.Internal,
			"failed response: %s", res.(*base.ResponseFailure).Message))
	}

	// successful renewal and confirmation
	return &colpb.CmdIndexNewResponse{
		Index: uint32(renewReq.Index),
	}, nil
}

func (s *debugService) CmdIndexActivate(ctx context.Context, req *colpb.CmdIndexActivateRequest,
) (*colpb.CmdIndexActivateResponse, error) {

	localIA := s.Topo.IA()
	errF := func(err error) (*colpb.CmdIndexActivateResponse, error) {
		return &colpb.CmdIndexActivateResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}

	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}
	if req.Index > 15 {
		return errF(status.Errorf(codes.Internal,
			"bad index number %d, not between 0 and 15", req.Index))
	}

	activateReq := base.NewRequest(s.now(), &rsv.ID, libcol.IndexNumber(req.Index), len(rsv.Steps))
	res, err := s.Store.InitActivateSegmentReservation(ctx, activateReq, rsv.Steps,
		rsv.TransportPath)
	if err != nil {
		return errF(status.Errorf(codes.Internal,
			"activating index: %v", err))
	}
	if !res.Success() {
		return errF(status.Errorf(codes.Internal,
			"failed response: %s", res.(*base.ResponseFailure).Message))
	}
	return &colpb.CmdIndexActivateResponse{}, nil
}

func (s *debugService) CmdIndexCleanup(ctx context.Context, req *colpb.CmdIndexCleanupRequest,
) (*colpb.CmdIndexCleanupResponse, error) {

	localIA := s.Topo.IA()
	errF := func(err error) (*colpb.CmdIndexCleanupResponse, error) {
		return &colpb.CmdIndexCleanupResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}

	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}
	if req.Index > 15 {
		return errF(status.Errorf(codes.Internal,
			"bad index number %d, not between 0 and 15", req.Index))
	}

	cleanupReq := base.NewRequest(s.now(), &rsv.ID, libcol.IndexNumber(req.Index), len(rsv.Steps))
	res, err := s.Store.InitCleanupSegmentReservation(ctx, cleanupReq, rsv.Steps, rsv.TransportPath)
	if err != nil {
		return errF(status.Errorf(codes.Internal,
			"cleaning index: %v", err))
	}
	if !res.Success() {
		return errF(status.Errorf(codes.Internal,
			"failed response: %s", res.(*base.ResponseFailure).Message))
	}
	return &colpb.CmdIndexCleanupResponse{}, nil
}

func (s *debugService) Traceroute(ctx context.Context, req *colpb.TracerouteRequest,
) (*colpb.TracerouteResponse, error) {

	localIA := s.Topo.IA()
	reqTimeStamp := uint64(time.Now().UnixMicro())
	errF := func(err error) (*colpb.TracerouteResponse, error) {
		return &colpb.TracerouteResponse{
			ErrorFound: &colpb.ErrorInIA{
				Ia:      uint64(localIA),
				Message: err.Error(),
			},
		}, nil
	}
	rsv, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return errF(err)
	}

	initiator := rsv.CurrentStep == 0 ||
		(rsv.PathType == libcol.DownPath && rsv.CurrentStep == len(rsv.Steps)-1)

	// only walk the reservation in reverse if it is a down path one and requested to do so.
	walkInReverse := req.DownDirection && rsv.PathType == libcol.DownPath

	var transport *colpath.ColibriPathMinimal
	if req.UseColibri {
		if initiator {
			// retrieve the colibri transport path here (this AS is source or initiator)
			transport = rsv.TransportPath
			if walkInReverse {
				transport, err = transport.ReverseAsColibri()
				if err != nil {
					return errF(status.Errorf(codes.Internal,
						"error reversing colibri path: %s\nFor path: %s", err, transport))
				}
			}
		} else {
			transport, err = colAddrFromCtx(ctx)
			if err != nil {
				return errF(status.Errorf(codes.Internal,
					"error retrieving path at transit: %s", err))
			}
			log.Debug("deleteme got a colibri transport from the network",
				"SRC", transport.Src,
				"DST", transport.Dst,
				"PATH", transport,
			)
		}
		if transport == nil {
			return errF(status.Errorf(codes.FailedPrecondition, "there is no colibri transport"))
		}

		// deleteme
		log.Debug("debug service info about the colibri transport path", "transport", transport)
	}

	egress := rsv.Egress()
	if walkInReverse {
		egress = rsv.Ingress()
	}

	res := &colpb.TracerouteResponse{}
	if egress != 0 { // destination not reached yet, forward to next debug service
		// TODO(juagargi) fix this by allowing a parameter.
		// XXX(juagargi) hacky: reduce the timeout by 100 ms to be able to answer back in
		// case of next hop timing out. This will work sometimes, when there had been no hop
		// that needs more than 100ms to send back the answer.
		deadline, _ := ctx.Deadline()
		ctx, cancelF := context.WithDeadline(ctx, deadline.Add(-100*time.Millisecond))
		defer cancelF()

		client, err := s.Operator.DebugClient(ctx, egress, transport)
		if err != nil {
			return errF(status.Errorf(codes.FailedPrecondition, "error using operator: %s", err))
		}

		res, err = client.Traceroute(ctx, req)
		if err != nil {
			return errF(status.Errorf(codes.Internal,
				"error forwarding to next (%s, egress_id = %d) service: %s",
				s.Operator.Neighbor(egress), egress, err))
		}
	}

	res.IaStamp = append(res.IaStamp, uint64(localIA))
	res.TimeStampFromRequest = append(res.TimeStampFromRequest, reqTimeStamp)
	res.TimeStampAtResponse = append(res.TimeStampAtResponse, uint64(time.Now().UnixMicro()))
	return res, nil
}

func (s *debugService) getSegR(ctx context.Context, id *colpb.ReservationID,
) (*segment.Reservation, error) {

	ID := translate.ID(id)
	segR, err := s.DB.GetSegmentRsvFromID(ctx, ID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error retrieving segment: %s", err)
	}
	if segR == nil {
		return nil, status.Errorf(codes.NotFound, "segment not found: %s", id)
	}
	return segR, nil
}
