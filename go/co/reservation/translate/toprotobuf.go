// Copyright 2021 ETH Zurich, Anapaya Systems
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

package translate

import (
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

func PBufSetupReq(req *segment.SetupReq) (*colpb.SegmentSetupRequest, error) {
	base, err := PBufRequest(&req.Request)
	if err != nil {
		return nil, err
	}
	return &colpb.SegmentSetupRequest{
		Base:   base,
		Params: PBufSetupRequestParams(req),
	}, nil
}

func PBufE2ERequest(req *e2e.Request) (*colpb.E2ERequest, error) {
	base, err := PBufRequest(&req.Request)
	if err != nil {
		return nil, err
	}
	return &colpb.E2ERequest{
		Base:    base,
		SrcHost: req.SrcHost,
		DstHost: req.DstHost,
	}, err
}

func PBufE2ESetupReq(req *e2e.SetupReq) (*colpb.E2ESetupRequest, error) {
	base, err := PBufE2ERequest(&req.Request)
	if err != nil {
		return nil, err
	}
	segs := make([]*colpb.ReservationID, len(req.SegmentRsvs))
	for i, id := range req.SegmentRsvs {
		segs[i] = PBufID(&id)
	}
	trail := make([]*colpb.E2ESetupRequest_E2ESetupBead, len(req.AllocationTrail))
	for i, b := range req.AllocationTrail {
		trail[i] = &colpb.E2ESetupRequest_E2ESetupBead{
			Maxbw: uint32(b),
		}
	}
	return &colpb.E2ESetupRequest{
		Base:        base,
		RequestedBw: uint32(req.RequestedBW),
		Params: &colpb.E2ESetupRequest_PathParams{
			Segments:       segs,
			CurrentSegment: uint32(req.CurrentSegmentRsvIndex),
		},
		Allocationtrail: trail,
	}, nil
}

func PBufSetupResponse(res segment.SegmentSetupResponse) *colpb.SegmentSetupResponse {
	msg := &colpb.SegmentSetupResponse{}

	switch r := res.(type) {
	case *segment.SegmentSetupResponseSuccess:
		msg.Timestamp = util.TimeToSecs(r.Timestamp)
		msg.Authenticators = PBufAuthenticators(r.AuthenticatedResponse.Authenticators)
		msg.SuccessFailure = &colpb.SegmentSetupResponse_Token{
			Token: r.Token.ToRaw(),
		}
	case *segment.SegmentSetupResponseFailure:
		msg.Timestamp = util.TimeToSecs(r.Timestamp)
		msg.Authenticators = PBufAuthenticators(r.AuthenticatedResponse.Authenticators)
		msg.SuccessFailure = &colpb.SegmentSetupResponse_Failure_{
			Failure: &colpb.SegmentSetupResponse_Failure{
				Request: PBufSetupRequestParams(r.FailedRequest),
				Failure: &colpb.Response_Failure{
					Message: r.Message,
				},
			},
		}
	}
	return msg
}

func PBufE2ESetupResponse(res e2e.SetupResponse) *colpb.E2ESetupResponse {
	msg := &colpb.E2ESetupResponse{}
	switch t := res.(type) {
	case *e2e.SetupResponseSuccess:
		msg.Timestamp = util.TimeToSecs(t.Timestamp)
		msg.Authenticators = PBufAuthenticators(t.Authenticators)
		msg.Token = t.Token
	case *e2e.SetupResponseFailure:
		msg.Timestamp = util.TimeToSecs(t.Timestamp)
		msg.Authenticators = PBufAuthenticators(t.Authenticators)
		trail := make([]*colpb.E2ESetupRequest_E2ESetupBead, len(t.AllocTrail))
		for i, b := range t.AllocTrail {
			trail[i] = &colpb.E2ESetupRequest_E2ESetupBead{
				Maxbw: uint32(b),
			}
		}
		msg.Failure = &colpb.E2ESetupResponse_Failure{
			Message:         t.Message,
			FailedStep:      uint32(t.FailedStep),
			Allocationtrail: trail,
		}
	}
	return msg
}

func PBufRequest(req *base.Request) (*colpb.Request, error) {
	p, err := PBufPath(req.Path)
	if err != nil {
		return nil, err
	}
	return &colpb.Request{
		Id:             PBufID(&req.ID),
		Index:          uint32(req.Index),
		Timestamp:      util.TimeToSecs(req.Timestamp),
		Path:           p,
		Authenticators: PBufAuthenticators(req.Authenticators),
	}, err
}

func PBufSetupRequestParams(req *segment.SetupReq) *colpb.SegmentSetupRequest_Params {
	return &colpb.SegmentSetupRequest_Params{
		ExpirationTime: util.TimeToSecs(req.ExpirationTime),
		Rlc:            uint32(req.RLC),
		PathType:       uint32(req.PathType),
		Minbw:          uint32(req.MinBW),
		Maxbw:          uint32(req.MaxBW),
		Splitcls:       uint32(req.SplitCls),
		PropsAtStart: &colpb.PathEndProps{
			Local:    req.PathProps.StartLocal(),
			Transfer: req.PathProps.StartTransfer(),
		},
		PropsAtEnd: &colpb.PathEndProps{
			Local:    req.PathProps.EndLocal(),
			Transfer: req.PathProps.EndTransfer(),
		},
		Allocationtrail:  PBufAllocTrail(req.AllocTrail),
		ReverseTraveling: req.ReverseTraveling,
	}
}

func PBufResponse(res base.Response) *colpb.Response {
	switch r := res.(type) {
	case *base.ResponseSuccess:
		return &colpb.Response{
			Timestamp:      util.TimeToSecs(r.Timestamp),
			Authenticators: PBufAuthenticators(r.Authenticators),
			SuccessFailure: &colpb.Response_Success_{},
		}
	case *base.ResponseFailure:
		return &colpb.Response{
			Timestamp:      util.TimeToSecs(r.Timestamp),
			Authenticators: PBufAuthenticators(r.Authenticators),
			SuccessFailure: &colpb.Response_Failure_{
				Failure: &colpb.Response_Failure{
					Message:    r.Message,
					FailingHop: uint32(r.FailedStep),
				},
			},
		}
	default:
		return nil
	}
}

func PBufListResponse(res []*colibri.ReservationLooks) *colpb.ListReservationsResponse {
	return &colpb.ListReservationsResponse{
		Reservations: PBufListReservationLooks(res),
	}
}

func PBufStitchableResponse(res *colibri.StitchableSegments) *colpb.ListStitchablesResponse {
	return &colpb.ListStitchablesResponse{
		SrcIa: uint64(res.SrcIA),
		DstIa: uint64(res.DstIA),
		Up:    PBufListReservationLooks(res.Up),
		Core:  PBufListReservationLooks(res.Core),
		Down:  PBufListReservationLooks(res.Down),
	}
}

func PBufListReservationLooks(
	res []*colibri.ReservationLooks) []*colpb.ListReservationsResponse_ReservationLooks {

	looks := make([]*colpb.ListReservationsResponse_ReservationLooks, len(res))
	for i, l := range res {
		looks[i] = &colpb.ListReservationsResponse_ReservationLooks{
			Id:             PBufID(&l.Id),
			SrcIa:          uint64(l.SrcIA),
			DstIa:          uint64(l.DstIA),
			ExpirationTime: util.TimeToSecs(l.ExpirationTime),
			Minbw:          uint32(l.MinBW),
			Maxbw:          uint32(l.MaxBW),
			Allocbw:        uint32(l.AllocBW),
			Splitcls:       uint32(l.Split),
			PathSteps:      PBufSteps(l.PathSteps),
		}
	}
	return looks
}

func PBufID(id *reservation.ID) *colpb.ReservationID {
	return &colpb.ReservationID{
		Asid:   uint64(id.ASID),
		Suffix: append(id.Suffix[:0:0], id.Suffix...),
	}
}

func PBufAuthenticators(auths [][]byte) *colpb.Authenticators {
	return &colpb.Authenticators{
		Macs: auths,
	}
}

func PBufAllocTrail(trail reservation.AllocationBeads) []*colpb.AllocationBead {
	beads := make([]*colpb.AllocationBead, len(trail))
	for i, bead := range trail {
		beads[i] = &colpb.AllocationBead{
			Allocbw: uint32(bead.AllocBW),
			Maxbw:   uint32(bead.MaxBW),
		}
	}
	return beads
}

func PBufPath(transp *base.TransparentPath) (*colpb.TransparentPath, error) {
	if transp == nil {
		return &colpb.TransparentPath{
			Steps: []*colpb.PathStep{},
		}, nil
	}
	buff, err := base.PathToRaw(transp.RawPath)
	if err != nil {
		return nil, err
	}

	return &colpb.TransparentPath{
		CurrentStep: uint32(transp.CurrentStep),
		Steps:       PBufSteps(transp.Steps),
		PathType:    uint32(transp.RawPath.Type()),
		RawPath:     buff,
	}, nil
}

func PBufSteps(steps []base.PathStep) []*colpb.PathStep {
	ret := make([]*colpb.PathStep, len(steps))
	for i, step := range steps {
		ret[i] = &colpb.PathStep{
			Ia:      uint64(step.IA),
			Ingress: uint32(step.Ingress),
			Egress:  uint32(step.Egress),
		}
	}
	return ret
}
