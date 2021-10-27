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

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Request struct {
	base.Request
	SrcHost net.IP
	DstHost net.IP
}

func (r *Request) Len() int {
	return r.Request.Len() + 16 + 16
}
func (r *Request) Serialize(buff []byte, writeMutableFields bool) {
	offset := r.Request.Len()
	r.Request.Serialize(buff[:offset], writeMutableFields)
	copy(buff[offset:], r.SrcHost.To16())
	offset += 16
	copy(buff[offset:], r.DstHost.To16())
}

// SetupReq is an e2e setup/renewal request, that has been so far accepted.
type SetupReq struct {
	Request
	RequestedBW            col.BWCls
	SegmentRsvs            []col.ID
	CurrentSegmentRsvIndex int // index in SegmentRsv above. Transfer nodes use the first segment
	AllocationTrail        []col.BWCls
	TransferIndices        []int // up to two indices (from Path) where the transfers are
}

func (r *SetupReq) Validate() error {
	if err := r.Request.Validate(); err != nil {
		return err
	}

	if !r.ID.IsE2EID() {
		return serrors.New("non e2e AS id in request", "asid", r.ID.ASID)
	}
	if len(r.SegmentRsvs) == 0 || len(r.SegmentRsvs) > 3 {
		return serrors.New("invalid number of segment reservations for an e2e request",
			"count", len(r.SegmentRsvs))
	}
	if r.SrcHost == nil || r.SrcHost.IsUnspecified() ||
		r.DstHost == nil || r.DstHost.IsUnspecified() {

		return serrors.New("empty fields not allowed", "src_host", r.SrcHost, "dst_host", r.DstHost)
	}
	return nil
}

// Len returns the length in bytes necessary to serialize the immutable fields.
func (r *SetupReq) Len() int {
	return r.Request.Len() + 1 + len(r.SegmentRsvs)*(reservation.IDSegLen)
}

func (r *SetupReq) Serialize(buff []byte, writeMutableFields bool) {
	if r == nil {
		return
	}

	offset := r.Request.Len()
	r.Request.Serialize(buff[:offset], writeMutableFields)
	buff[offset] = byte(r.RequestedBW)
	offset++
	// segments:
	for _, id := range r.SegmentRsvs {
		n, _ := id.Read(buff[offset:])
		if n != reservation.IDSegLen {
			panic(fmt.Sprintf("inconsistent id length %d (should be %d)",
				n, reservation.IDSegLen))
		}
		offset += reservation.IDSegLen
	}
}

type SetupFailureInfo struct {
	NodeIndex int
	Message   string
}
