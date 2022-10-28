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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/coliquic"
	"github.com/scionproto/scion/go/lib/log"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type DebugService struct {
	DB       backend.DB
	Operator *coliquic.ServiceClientOperator
	Topo     *topology.Loader
	Store    reservationstorage.Store
}

var _ colpb.ColibriDebugCommandsServer = (*DebugService)(nil)
var _ colpb.ColibriDebugServiceServer = (*DebugService)(nil)

func (s *DebugService) CmdTraceroute(ctx context.Context, req *colpb.TracerouteRequest,
) (*colpb.TracerouteResponse, error) {

	return s.Traceroute(ctx, req)
}

func (s *DebugService) Traceroute(ctx context.Context, req *colpb.TracerouteRequest,
) (*colpb.TracerouteResponse, error) {

	localIA := s.Topo.IA()
	reqTimeStamp := uint64(time.Now().UnixMicro())
	segR, err := s.getSegR(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	var colibriTransport *colpath.ColibriPathMinimal
	if req.UseColibri {
		if segR.CurrentStep == 0 {
			// since this is the source of the traffic, retrieve the colibri transport path here
			colibriTransport = segR.TransportPath
		} else {
			colibriTransport, err = colPathFromCtx(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"error retrieving path at transit: %s", err)
			}
		}
		if colibriTransport == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "there is no colibri transport")
		}
		// deleteme
		log.Debug("debug service info about the colibri transport path",
			"S", colibriTransport.InfoField.S,
			"C", colibriTransport.InfoField.C,
			"R", colibriTransport.InfoField.R,
			"expiration", util.SecsToTime(colibriTransport.InfoField.ExpTick),
			"curr_hopfield", colibriTransport.InfoField.CurrHF,
			"idx", colibriTransport.InfoField.Ver,
			"bwcls", colibriTransport.InfoField.BwCls,
		)
	}

	res := &colpb.TracerouteResponse{}
	if segR.Egress() != 0 {
		// not finished yet, forward to next debug service
		client, err := s.Operator.DebugClient(ctx, segR.Egress(), colibriTransport)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "error using operator: %s", err)
		}
		res, err = client.Traceroute(ctx, req)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "error forwarding to next service: %s", err)
		}
	}

	res.AsStamp = append(res.AsStamp, uint64(localIA))
	res.TimeStampFromRequest = append(res.TimeStampFromRequest, reqTimeStamp)
	res.TimeStampAtResponse = append(res.TimeStampAtResponse, uint64(time.Now().UnixMicro()))
	return res, nil
}

func (s *DebugService) getSegR(ctx context.Context, id *colpb.ReservationID,
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
