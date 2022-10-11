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
	"fmt"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

func SetupReq(msg *colpb.SegmentSetupRequest, transportPath *colpath.ColibriPathMinimal,
) (*segment.SetupReq, error) {
	if msg == nil || msg.Base == nil || msg.Params == nil {
		return nil, serrors.New("incomplete message", "msg", msg)
	}
	baseReq, err := Request(msg.Base)
	if err != nil {
		return nil, err
	}
	expTime, rlc, pathType, minbw, maxbw, splitcls, pathProps, allocTrail, revTravel, err :=
		segmentSetupRequest_Params(msg.Params)
	if err != nil {
		return nil, err
	}
	req := &segment.SetupReq{
		Request:          *baseReq,
		ExpirationTime:   expTime,
		RLC:              rlc,
		PathType:         pathType,
		MinBW:            minbw,
		MaxBW:            maxbw,
		SplitCls:         splitcls,
		PathProps:        pathProps,
		AllocTrail:       allocTrail,
		ReverseTraveling: revTravel,
		Steps:            PathSteps(msg.Params.Steps),
		CurrentStep:      int(msg.Params.CurrentStep) + 1,
		TransportPath:    transportPath,
	}
	return req, nil
}

func E2ERequest(msg *colpb.E2ERequest) (*e2e.Request, error) {
	baseReq, err := Request(msg.Base)
	if err != nil {
		return nil, err
	}
	return &e2e.Request{
		Request: *baseReq,
		SrcHost: msg.SrcHost,
		DstHost: msg.DstHost,
	}, nil
}

func E2ESetupRequest(msg *colpb.E2ESetupRequest) (*e2e.SetupReq, error) {
	base, err := E2ERequest(msg.Base)
	if err != nil {
		return nil, err
	}
	segIds := make([]col.ID, len(msg.Params.Segments))
	for i, s := range msg.Params.Segments {
		segIds[i] = *ID(s)
	}
	trail := make([]col.BWCls, len(msg.Allocationtrail))
	for i, b := range msg.Allocationtrail {
		trail[i] = col.BWCls(b.Maxbw)
	}
	return &e2e.SetupReq{
		Request:                *base,
		SegmentRsvs:            segIds,
		CurrentSegmentRsvIndex: int(msg.Params.CurrentSegment),
		Steps:                  PathSteps(msg.Params.Steps),
		CurrentStep:            int(msg.Params.CurrentStep),
		RequestedBW:            col.BWCls(msg.RequestedBw),
		AllocationTrail:        trail,
	}, nil
}

func SetupResponse(msg *colpb.SegmentSetupResponse) (segment.SegmentSetupResponse, error) {
	var res segment.SegmentSetupResponse
	switch oneof := msg.SuccessFailure.(type) {
	case *colpb.SegmentSetupResponse_Token:
		tok, err := col.TokenFromRaw(oneof.Token)
		if err != nil {
			return nil, err
		}
		res = &segment.SegmentSetupResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      util.SecsToTime(msg.Timestamp),
				Authenticators: msg.Authenticators.Macs,
			},
			Token: *tok,
		}
	case *colpb.SegmentSetupResponse_Failure_:
		expTime, rlc, pathType, minbw, maxbw, splitcls, pathProps, allocTrail, revTravel, err :=
			segmentSetupRequest_Params(oneof.Failure.Request)
		if err != nil {
			return nil, err
		}
		res = &segment.SegmentSetupResponseFailure{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      util.SecsToTime(msg.Timestamp),
				Authenticators: msg.Authenticators.Macs,
			},
			FailedStep: uint8(oneof.Failure.Failure.FailingHop),
			FailedRequest: &segment.SetupReq{ // without base request
				ExpirationTime:   expTime,
				RLC:              rlc,
				PathType:         pathType,
				MinBW:            minbw,
				MaxBW:            maxbw,
				SplitCls:         splitcls,
				PathProps:        pathProps,
				AllocTrail:       allocTrail,
				ReverseTraveling: revTravel,
			},
			Message: oneof.Failure.Failure.Message,
		}
	}
	return res, nil
}

func E2ESetupResponse(msg *colpb.E2ESetupResponse) (e2e.SetupResponse, error) {
	if msg.Failure != nil {
		trail := make([]col.BWCls, len(msg.Failure.Allocationtrail))
		for i, b := range msg.Failure.Allocationtrail {
			trail[i] = col.BWCls(b.Maxbw)
		}
		return &e2e.SetupResponseFailure{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      util.SecsToTime(msg.Timestamp),
				Authenticators: msg.Authenticators.Macs,
			},
			Message:    msg.Failure.Message,
			FailedStep: uint8(msg.Failure.FailedStep),
			AllocTrail: trail,
		}, nil
	}
	// success:
	return &e2e.SetupResponseSuccess{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      util.SecsToTime(msg.Timestamp),
			Authenticators: msg.Authenticators.Macs,
		},
		Token: msg.Token,
	}, nil
}

func Request(msg *colpb.Request) (*base.Request, error) {
	idx, err := Index(msg.Index)
	if err != nil {
		return nil, err
	}
	timestamp := util.SecsToTime(msg.Timestamp)
	return &base.Request{
		MsgId: base.MsgId{
			ID:        *ID(msg.Id),
			Index:     idx,
			Timestamp: timestamp,
		},
		Authenticators: msg.Authenticators.Macs,
	}, nil
}

func Response(msg *colpb.Response) base.Response {
	authResponse := base.AuthenticatedResponse{
		Timestamp:      util.SecsToTime(msg.Timestamp),
		Authenticators: msg.Authenticators.Macs,
	}
	switch r := msg.SuccessFailure.(type) {
	case *colpb.Response_Success_:
		return &base.ResponseSuccess{
			AuthenticatedResponse: authResponse,
		}
	case *colpb.Response_Failure_:
		return &base.ResponseFailure{
			AuthenticatedResponse: authResponse,
			FailedStep:            uint8(r.Failure.FailingHop),
			Message:               r.Failure.Message,
		}
	default:
		panic(fmt.Sprintf("unknown type %s", common.TypeOf(msg.SuccessFailure)))
	}
}

func StitchableSegments(msg *colpb.ListStitchablesResponse) (*colibri.StitchableSegments, error) {
	up, err := ReservationLooks(msg.Up)
	if err != nil {
		return nil, err
	}
	core, err := ReservationLooks(msg.Core)
	if err != nil {
		return nil, err
	}
	down, err := ReservationLooks(msg.Down)
	if err != nil {
		return nil, err
	}
	return &colibri.StitchableSegments{
		SrcIA: addr.IA(msg.SrcIa),
		DstIA: addr.IA(msg.DstIa),
		Up:    up,
		Core:  core,
		Down:  down,
	}, nil
}

func ListResponse(msg *colpb.ListReservationsResponse) ([]*colibri.ReservationLooks, error) {
	return ReservationLooks(msg.Reservations)
}

func ReservationLooks(msg []*colpb.ListReservationsResponse_ReservationLooks) (
	[]*colibri.ReservationLooks, error) {

	res := make([]*colibri.ReservationLooks, len(msg))
	for i, l := range msg {
		res[i] = &colibri.ReservationLooks{
			Id:             *ID(l.Id),
			SrcIA:          addr.IA(l.SrcIa),
			DstIA:          addr.IA(l.DstIa),
			ExpirationTime: util.SecsToTime(l.ExpirationTime),
			MinBW:          col.BWCls(l.Minbw),
			MaxBW:          col.BWCls(l.Maxbw),
			AllocBW:        col.BWCls(l.Allocbw),
			Split:          col.SplitCls(l.Splitcls),
			PathSteps:      PathSteps(l.PathSteps),
		}
	}
	return res, nil
}

func Index(msg uint32) (col.IndexNumber, error) {
	idx := col.IndexNumber(msg)
	if uint32(idx) != msg {
		return 0, serrors.New("index is out of range", "idx", msg)
	}
	return idx, idx.Validate()
}

func RLC(msg uint32) (col.RLC, error) {
	rlc := col.RLC(msg)
	if uint32(rlc) != msg {
		return 0, serrors.New("rlc is out of range", "rlc", rlc)
	}
	return rlc, rlc.Validate()
}

func PathType(msg uint32) (col.PathType, error) {
	pt := col.PathType(msg)
	if uint32(pt) != msg {
		return 0, serrors.New("path type is out of range", "path_type", pt)
	}
	return pt, pt.Validate()
}

func BW(msg uint32) (col.BWCls, error) {
	bw := col.BWCls(msg)
	if uint32(bw) != msg {
		return 0, serrors.New("bw class is out of range", "bw", msg)
	}
	return bw, bw.Validate()
}

func SplitCls(msg uint32) (col.SplitCls, error) {
	sc := col.SplitCls(msg)
	if uint32(sc) != msg {
		return 0, serrors.New("split class is out of range", "class", msg)
	}
	return sc, nil
}

func ID(msg *colpb.ReservationID) *col.ID {
	return &col.ID{
		ASID:   addr.AS(msg.Asid),
		Suffix: append([]byte{}, msg.Suffix...),
	}
}

func Token(msg *colpb.SegmentSetupResponse_Token) (*col.Token, error) {
	return col.TokenFromRaw(msg.Token)
}

func AllocTrail(msg []*colpb.AllocationBead) col.AllocationBeads {
	trail := make(col.AllocationBeads, len(msg))
	for i, bead := range msg {
		trail[i] = col.AllocationBead{
			AllocBW: col.BWCls(bead.Allocbw),
			MaxBW:   col.BWCls(bead.Maxbw),
		}
	}
	return trail
}

func PathSteps(msg []*colpb.PathStep) base.PathSteps {
	steps := make(base.PathSteps, len(msg))
	for i, step := range msg {
		steps[i].IA = addr.IA(step.Ia)
		steps[i].Ingress = uint16(step.Ingress)
		steps[i].Egress = uint16(step.Egress)
	}
	return steps
}

func segmentSetupRequest_Params(msg *colpb.SegmentSetupRequest_Params) (expTime time.Time,
	rlc col.RLC, pathType col.PathType, minbw col.BWCls, maxbw col.BWCls, splitcls col.SplitCls,
	pathProps col.PathEndProps, allocTrail col.AllocationBeads, revTravel bool, err error) {

	expTime = util.SecsToTime(msg.ExpirationTime)
	rlc, err = RLC(msg.Rlc)
	if err != nil {
		return
	}
	pathType, err = PathType(msg.PathType)
	if err != nil {
		return
	}
	minbw, err = BW(msg.Minbw)
	if err != nil {
		return
	}
	maxbw, err = BW(msg.Maxbw)
	if err != nil {
		return
	}
	splitcls, err = SplitCls(msg.Splitcls)
	if err != nil {
		return
	}
	pathProps = col.NewPathEndProps(
		msg.PropsAtStart.Local,
		msg.PropsAtStart.Transfer,
		msg.PropsAtEnd.Local,
		msg.PropsAtEnd.Transfer)
	allocTrail = AllocTrail(msg.Allocationtrail)
	revTravel = msg.ReverseTraveling
	return
}
