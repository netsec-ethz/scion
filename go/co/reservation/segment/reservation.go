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

package segment

import (
	"bytes"
	"fmt"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

// Reservation represents a segment reservation.
type Reservation struct {
	ID            reservation.ID
	Indices       Indices                  // existing indices in this reservation
	activeIndex   int                      // -1 <= activeIndex < len(Indices)
	PathType      reservation.PathType     // the type of path (up,core,down)
	PathEndProps  reservation.PathEndProps // the properties for stitching and start/end
	TrafficSplit  reservation.SplitCls     // the traffic split between control and data planes
	Steps         base.PathSteps           // recovered from the pb messages
	CurrentStep   int
	TransportPath *colpath.ColibriPathMinimal // only used at initiator AS
}

func NewReservation(asid addr.AS) *Reservation {
	return &Reservation{
		ID: reservation.ID{
			ASID:   asid,
			Suffix: make([]byte, reservation.IDSuffixSegLen),
		},
		activeIndex: -1,
	}
}

func (r *Reservation) Ingress() uint16 {
	return r.Steps[r.CurrentStep].Ingress
}

func (r *Reservation) Egress() uint16 {
	return r.Steps[r.CurrentStep].Egress
}

// deriveColibriPathAtSource creates the ColibriPathMinimal from the active index in this
// reservation. If there is no active index, the path is nil.
func (r *Reservation) deriveColibriPathAtSource() *colpath.ColibriPathMinimal {
	index := r.ActiveIndex()
	if index == nil {
		return nil
	}
	p := &colpath.ColibriPath{
		InfoField: r.deriveInfoField(),
		HopFields: make([]*colpath.HopField, len(index.Token.HopFields)),
	}
	for i, hf := range index.Token.HopFields {
		p.HopFields[i] = &colpath.HopField{
			IngressId: hf.Ingress,
			EgressId:  hf.Egress,
			Mac:       append([]byte{}, hf.Mac[:]...),
		}
	}
	min, err := p.ToMinimal()
	if err != nil {
		return nil
	}
	return min
}

// deriveColibriPathAtDestination creates the ColibriPath using the values of the active index in
// this reservation, but with the hop fields in the reverse order. If there is no active index it
// returns nil.
func (r *Reservation) deriveColibriPathAtDestination() *colpath.ColibriPathMinimal {
	index := r.ActiveIndex()
	if index == nil {
		return nil
	}

	p := &colpath.ColibriPath{
		InfoField: r.deriveInfoField(),
		HopFields: make([]*colpath.HopField, len(index.Token.HopFields)),
	}
	lhf := len(index.Token.HopFields)
	for i := 0; i < lhf; i++ {
		hf := index.Token.HopFields[lhf-i-1]
		p.HopFields[i] = &colpath.HopField{
			IngressId: hf.Ingress,
			EgressId:  hf.Egress,
			Mac:       append([]byte{}, hf.Mac[:]...),
		}
	}
	// because the initiator AS is actually the DstAS, reverse the path
	if _, err := p.Reverse(); err != nil {
		return nil
	}
	min, err := p.ToMinimal()
	if err != nil {
		return nil
	}
	return min
}

func (r *Reservation) DeriveColibriPath() *colpath.ColibriPathMinimal {
	if r.PathType == reservation.DownPath {
		return r.deriveColibriPathAtDestination()
	}
	return r.deriveColibriPathAtSource()
}

// Validate will return an error for invalid values.
func (r *Reservation) Validate() error {
	if r == nil {
		return nil
	}
	if r.ID.ASID == 0 {
		return serrors.New("Reservation ID not set")
	}
	if err := base.ValidateIndices(r.Indices); err != nil {
		return err
	}
	if r.activeIndex < -1 || r.activeIndex > 0 || r.activeIndex >= len(r.Indices) {
		// when we activate an index all previous indices are removed.
		// Thus activeIndex can only be -1 or 0
		return serrors.New("invalid active index", "active_index", r.activeIndex)
	}
	activeIndex := -1
	for i, index := range r.Indices {
		if index.State == IndexActive {
			if activeIndex != -1 {
				return serrors.New("more than one active index",
					"first_active", r.Indices[activeIndex].Idx, "another_active", index.Idx)
			}
			activeIndex = i
		}
	}
	if r.Steps == nil || len(r.Steps) < 2 {
		return serrors.New("Wrong steps state")
	}
	if r.Steps[0].Ingress != 0 {
		return serrors.New("Wrong interface for srcIA ingress",
			"ingress", r.Steps[0].Ingress)
	}
	if r.Steps[len(r.Steps)-1].Egress != 0 {
		return serrors.New("Wrong interface for dstIA egress",
			"egress", r.Steps[len(r.Steps)-1].Egress)
	}
	if in, eg := base.InEgFromDataplanePath(r.TransportPath); in != r.Ingress() ||
		eg != r.Egress() {
		return serrors.New("Inconsistent ingress/egress from dataplane and reservation",
			"dataplane_in", in, "reservation_in", r.Ingress(),
			"dataplane_eg", eg, "reservation_eg", r.Egress())
	}

	err := r.PathEndProps.Validate()
	if err != nil {
		return serrors.WrapStr("validating reservation, end properties failed", err)
	}
	return nil
}

// ActiveIndex returns the currently active Index for this reservation, or nil if none.
func (r *Reservation) ActiveIndex() *Index {
	if r.activeIndex == -1 {
		return nil
	}
	return &r.Indices[r.activeIndex]
}

// NewIndex creates a new index. The associated token is created from the arguments, and
// automatically linked to the index.
// The expiration times must always be greater or equal than those in previous indices.
func (r *Reservation) NewIndex(idx reservation.IndexNumber,
	expTime time.Time, minBW, maxBW, allocBW reservation.BWCls,
	rlc reservation.RLC, pathType reservation.PathType) (reservation.IndexNumber, error) {

	// idx := reservation.IndexNumber(0)
	// if len(r.Indices) > 0 {
	// 	idx = r.Indices[len(r.Indices)-1].Idx.Add(1)
	// }
	tok := &reservation.Token{
		InfoField: reservation.InfoField{
			Idx:            idx,
			ExpirationTick: reservation.TickFromTime(expTime),
			BWCls:          allocBW,
			RLC:            rlc,
			PathType:       pathType,
		},
	}
	index := NewIndex(idx, expTime, IndexTemporary, minBW, maxBW, allocBW, tok)
	return r.addIndex(index)
}

// Index finds the Index with that IndexNumber and returns a pointer to it.
func (r *Reservation) Index(idx reservation.IndexNumber) *Index {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return nil
	}
	return &r.Indices[sliceIndex]
}

func (r *Reservation) NextIndexToRenew() reservation.IndexNumber {
	last := reservation.IndexNumber(0).Sub(1)
	if len(r.Indices) > 0 {
		last = r.Indices[len(r.Indices)-1].Idx
	}
	return last.Add(1)
}

func (r *Reservation) NextIndexToActivate() *Index {
	switch {
	case len(r.Indices) == 0:
		return nil
	case r.activeIndex < 0:
		return &r.Indices[len(r.Indices)-1]
	case r.activeIndex+1 < len(r.Indices):
		return &r.Indices[r.activeIndex+1]
	}
	return nil
}

// SetIndexConfirmed sets the index as IndexPending (confirmed but not active). If the requested
// index has state active, it will emit an error.
func (r *Reservation) SetIndexConfirmed(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	if r.Indices[sliceIndex].State == IndexActive {
		return serrors.New("cannot confirm an already active index", "index_number", idx)
	}
	r.Indices[sliceIndex].State = IndexPending
	return nil
}

// SetIndexActive sets the index as active. If the reservation had already an active state,
// it will remove all previous indices.
func (r *Reservation) SetIndexActive(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	if r.activeIndex == sliceIndex {
		return nil // already active
	}
	// valid states are Pending (nominal) and Active (reconstructing from DB needs this)
	if r.Indices[sliceIndex].State != IndexPending && r.Indices[sliceIndex].State != IndexActive {
		return serrors.New("attempt to activate a non confirmed index", "index_number", idx,
			"state", r.Indices[sliceIndex].State)
	}
	if r.activeIndex > -1 {
		if r.activeIndex > sliceIndex {
			return serrors.New("activating a past index",
				"last active", r.Indices[r.activeIndex].Idx, "current", idx)
		}
	}
	// remove indices [lastActive,currActive) so that currActive is at position 0
	r.Indices = r.Indices[sliceIndex:]
	r.activeIndex = 0
	r.Indices[0].State = IndexActive
	return nil
}

func (r *Reservation) SetIndexInactive() {
	if r.activeIndex == 0 {
		r.Indices[0].State = IndexPending
		r.activeIndex = -1
	}
}

// RemoveIndex removes all indices from the beginning until this one, inclusive.
func (r *Reservation) RemoveIndex(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	r.Indices = r.Indices[sliceIndex+1:]

	if r.activeIndex > sliceIndex { // if active index was not removed, adjust it
		r.activeIndex -= (sliceIndex + 1)
	} else { // if active index was removed, no active index
		r.activeIndex = -1
	}
	return nil
}

func (r *Reservation) String() string {
	return fmt.Sprintf("%s, Idxs: [%s]", r.ID.String(), r.Indices)
}

// MaxBlockedBW returns the maximum bandwidth blocked by this reservation, which is
// the same as the maximum allocated bandwidth indicated by its indices.
func (r *Reservation) MaxBlockedBW() uint64 {
	if len(r.Indices) == 0 {
		return 0
	}
	var max reservation.BWCls
	for _, idx := range r.Indices {
		max = reservation.MaxBWCls(max, idx.AllocBW)
	}
	return max.ToKbps()
}

// MaxRequestedBW returns the maximum bandwidth requested by this reservation.
func (r *Reservation) MaxRequestedBW() uint64 {
	if len(r.Indices) == 0 {
		return 0
	}
	var max reservation.BWCls
	for _, idx := range r.Indices {
		max = reservation.MaxBWCls(max, idx.MaxBW)
	}
	return max.ToKbps()
}

func (r *Reservation) addIndex(index *Index) (reservation.IndexNumber, error) {
	newIndices := make(Indices, len(r.Indices)+1)
	copy(newIndices, r.Indices)
	newIndices[len(newIndices)-1] = *index
	if err := base.ValidateIndices(newIndices); err != nil {
		return 0, err
	}
	r.Indices = newIndices
	return index.Idx, nil
}

// deriveInfoField returns a colibri info field filled with the values from this reservation.
// It returns nil if there is no active index.
func (r *Reservation) deriveInfoField() *colpath.InfoField {
	index := r.ActiveIndex()
	if index == nil {
		return nil
	}
	return &colpath.InfoField{
		C:       true,
		S:       true,
		Ver:     uint8(index.Idx),
		HFCount: uint8(len(index.Token.HopFields)),
		// the SegR ID and then 8 zeroes:
		ResIdSuffix: append(append(r.ID.Suffix[:0:0], r.ID.Suffix...),
			bytes.Repeat([]byte{0}, colpath.LenSuffix-reservation.IDSuffixSegLen)...),
		ExpTick: uint32(index.Token.ExpirationTick),
		BwCls:   uint8(index.AllocBW),
		Rlc:     uint8(index.Token.RLC),
	}
}
