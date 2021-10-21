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

// Package colibri contains methods for the creation and verification of the colibri packet
// timestamp and validation fields.
package colibri

import (
	"fmt"
	"strings"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

// TODO(juagargi) rename to something like SegRsvInfo
type ReservationLooks struct {
	Id             reservation.ID
	SrcIA          addr.IA // might be different than the Id.ASID if the segment is e.g. down
	DstIA          addr.IA
	ExpirationTime time.Time
	MinBW          reservation.BWCls
	MaxBW          reservation.BWCls
	AllocBW        reservation.BWCls
	Split          reservation.SplitCls
	PathSteps      []base.PathStep
}

func (l *ReservationLooks) Copy() *ReservationLooks {
	tmp := *l
	return &tmp
}

// StitchableSegments is a collection of up, core and down segments that could be stitched
// to reach a destination, after a combination process.
type StitchableSegments struct {
	SrcIA          addr.IA
	DstIA          addr.IA
	Up, Core, Down []*ReservationLooks
}

func (s *StitchableSegments) String() string {
	printSegments := func(dir string, segments []*ReservationLooks) []string {
		strs := make([]string, len(segments))
		for i, s := range segments {
			strs[i] = fmt.Sprintf("[%3d] %6s %s: %s -> %s (until %s, [max,min,alloc]=[%d,%d,%d])",
				i, dir, s.Id, s.SrcIA, s.DstIA, s.ExpirationTime, s.MaxBW, s.MinBW, s.AllocBW)
		}
		return strs
	}
	msgs := []string{fmt.Sprintf("%s -> %s", s.SrcIA, s.DstIA)}
	msgs = append(msgs, printSegments("up,", s.Up)...)
	msgs = append(msgs, printSegments("core,", s.Core)...)
	msgs = append(msgs, printSegments("down,", s.Down)...)
	return strings.Join(msgs, "\n")
}

func (s *StitchableSegments) Copy() *StitchableSegments {
	return &StitchableSegments{
		SrcIA: s.SrcIA,
		DstIA: s.DstIA,
		Up:    copyReservationLooks(s.Up),
		Core:  copyReservationLooks(s.Core),
		Down:  copyReservationLooks(s.Down),
	}
}

func copyReservationLooks(rsvs []*ReservationLooks) []*ReservationLooks {
	ret := make([]*ReservationLooks, len(rsvs))
	for i, r := range rsvs {
		ret[i] = r.Copy()
	}
	return ret
}
