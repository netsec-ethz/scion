// Copyright 2020 ETH Zurich, Anapaya Systems
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

package e2e

import (
	"fmt"
	"net"
	"strings"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	caddr "github.com/scionproto/scion/go/lib/slayers/path/colibri/addr"
)

// Reservation represents an E2E reservation.
type Reservation struct {
	ID                  reservation.ID
	Steps               base.PathSteps         // used to find the current AS
	CurrentStep         int                    // a given AS appears only once inside Steps
	SegmentReservations []*segment.Reservation // stitched segment reservations
	Indices             Indices
}

func (r *Reservation) Ingress() uint16 {
	return r.Steps[r.CurrentStep].Ingress
}

func (r *Reservation) Egress() uint16 {
	return r.Steps[r.CurrentStep].Egress
}

func (r *Reservation) IsFirstAS() bool {
	return r.CurrentStep == 0
}

func (r *Reservation) IsLastAS() bool {
	return r.CurrentStep == len(r.Steps)-1
}

// IsStitchPoint returns true if the AS represented by ia is a stitch point.
// The stitching points are present at the end of a segment and beginning of another one.
func (r *Reservation) IsStitchPoint(ia addr.IA) bool {
	if len(r.SegmentReservations) != 2 {
		return false
	}
	return r.SegmentReservations[0].Steps.DstIA() == ia &&
		r.SegmentReservations[1].Steps.SrcIA() == ia
}

func (r *Reservation) String() string {
	if r == nil {
		return "<nil>"
	}
	segs := make([]string, len(r.SegmentReservations))
	for i, s := range r.SegmentReservations {
		segs[i] = fmt.Sprintf("%s (%d indices) (%s)",
			s.ID,
			len(s.Indices),
			s.Steps,
		)
	}
	return fmt.Sprintf("%s: %d segment(s): {%s} . IDXS: [%s]",
		r.ID, len(r.SegmentReservations), strings.Join(segs, "; "), r.Indices)
}

// Validate will return an error for invalid values.
// It does not check for valid path properties and correct end/start AS ID when stitching.
func (r *Reservation) Validate() error {
	if err := base.ValidateIndices(r.Indices); err != nil {
		return err
	}
	if len(r.SegmentReservations) < 1 || len(r.SegmentReservations) > 2 {
		return serrors.New("wrong number of segment reservations referenced in E2E reservation",
			"number", len(r.SegmentReservations))
	}
	for i, rsv := range r.SegmentReservations {
		if rsv == nil {
			return serrors.New("invalid segment reservation referenced by e2e, is nil",
				"slice_index", i)
		}
		if err := rsv.Validate(); err != nil {
			return serrors.New("invalid segment reservation referenced by e2e one",
				"slice_index", i, "segment_id", rsv.ID)
		}
	}
	return nil
}

// NewIndex creates a new index in this reservation. The token needs to be created manually.
func (r *Reservation) NewIndex(expTime time.Time, bw reservation.BWCls) (
	reservation.IndexNumber, error) {

	idx := reservation.IndexNumber(0)
	if len(r.Indices) > 0 {
		idx = r.Indices[len(r.Indices)-1].Idx.Add(1)
	}
	newIndices := make(Indices, len(r.Indices)+1)
	copy(newIndices, r.Indices)
	newIndices[len(newIndices)-1] = Index{
		Expiration: expTime,
		Idx:        idx,
		AllocBW:    bw,
		Token: &reservation.Token{
			InfoField: reservation.InfoField{
				Idx:            idx,
				ExpirationTick: reservation.TickFromTime(expTime),
				BWCls:          bw,
				RLC:            0,
				PathType:       reservation.E2EPath,
			},
		},
	}
	if err := base.ValidateIndices(newIndices); err != nil {
		return 0, err
	}
	r.Indices = newIndices
	return idx, nil
}

// RemoveIndex removes all indices from the beginning until this one, inclusive.
func (r *Reservation) RemoveIndex(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	r.Indices = r.Indices[sliceIndex+1:]
	return nil
}

// Index finds the Index with that IndexNumber and returns a pointer to it. Nil if not found.
func (r *Reservation) Index(idx reservation.IndexNumber) *Index {
	if r == nil {
		return nil
	}
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return nil
	}
	return &r.Indices[sliceIndex]
}

// AllocResv returns the allocated bandwidth by this reservation using the current active index and
// the previous one. The max of those two values is used because the current active index might
// be rolled back with a cleanup request. The return units is Kbps.
func (r *Reservation) AllocResv() uint64 {
	var maxBW reservation.BWCls
	switch len(r.Indices) {
	case 0:
		return 0
	case 1:
		maxBW = r.Indices[len(r.Indices)-1].AllocBW
	default:
		maxBW = reservation.MaxBWCls(r.Indices[len(r.Indices)-1].AllocBW,
			r.Indices[len(r.Indices)-2].AllocBW)
	}
	return maxBW.ToKbps()
}

func (r *Reservation) DstIA() addr.IA {
	if len(r.SegmentReservations) == 0 {
		return 0
	}
	return r.SegmentReservations[len(r.SegmentReservations)-1].Steps.DstIA()
}

// GetLastSegmentPathSteps returns the path steps for the last segment in use by this e2e rsv.
func (r *Reservation) GetLastSegmentPathSteps() []base.PathStep {
	seg := r.SegmentReservations[len(r.SegmentReservations)-1]
	steps := append([]base.PathStep{}, seg.Steps...)
	return steps
}

// DeriveColibriPath builds a valid colibi path based on the arguments.
func DeriveColibriPath(id *reservation.ID, srcIA addr.IA, srcHost net.IP,
	dstIA addr.IA, dstHost net.IP, tok *reservation.Token) *colpath.ColibriPath {

	p := &colpath.ColibriPath{
		InfoField: &colpath.InfoField{
			C:           false,
			S:           false,
			R:           false,
			Ver:         uint8(tok.Idx),
			HFCount:     uint8(len(tok.HopFields)),
			ResIdSuffix: make([]byte, 12),
			ExpTick:     uint32(tok.ExpirationTick),
			BwCls:       uint8(tok.BWCls),
			Rlc:         uint8(tok.RLC),
		},
		HopFields: make([]*colpath.HopField, len(tok.HopFields)),
		Src:       caddr.NewEndpointWithIP(srcIA, srcHost),
		Dst:       caddr.NewEndpointWithIP(dstIA, dstHost),
	}
	copy(p.InfoField.ResIdSuffix, id.Suffix)
	for i, hf := range tok.HopFields {
		p.HopFields[i] = &colpath.HopField{
			IngressId: hf.Ingress,
			EgressId:  hf.Egress,
			Mac:       append([]byte{}, hf.Mac[:]...),
		}
	}
	return p
}
