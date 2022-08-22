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
	// XXX(JordiSubira): There's not a simple way to extract
	// the current step from the dataplane. Thus it is conveyed
	// as part of the request.
	CurrentStep int
	Steps       base.PathSteps
}

func (r *Request) Len() int {
	return r.Request.Len() + 16 + 16 + r.Steps.Size()
}
func (r *Request) Serialize(buff []byte, options base.SerializeOptions) {
	offset := r.Request.Len()
	r.Request.Serialize(buff[:offset], options)
	copy(buff[offset:], r.SrcHost.To16())
	offset += 16
	copy(buff[offset:], r.DstHost.To16())
	offset += 16
	r.Steps.Serialize(buff[offset:])
}

func (r *Request) Validate() error {
	if len(r.Steps) < 2 {
		return serrors.New("Wrong steps state")
	}
	return r.Request.Validate(r.Steps)
}

func (r *Request) IsFirstAS() bool {
	return r.CurrentStep == 0
}

func (r *Request) IsLastAS() bool { // override the use of the RequestMetadata.path with PathToDst
	return r.CurrentStep >= len(r.Steps)-1
}

// Ingress returns the ingress interface of this step for this request.
// Do not call Ingress without validating the request first.
func (r *Request) Ingress() uint16 {
	return r.Steps[r.CurrentStep].Ingress
}

// Egress returns the egress interface of this step for this request.
// Do not call Egress without validating the request first.
func (r *Request) Egress() uint16 {
	return r.Steps[r.CurrentStep].Egress
}

func (r *Request) CurrentValidatorField() []byte {
	return r.Authenticators[r.CurrentStep-1]
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

func (r *SetupReq) Serialize(buff []byte, options base.SerializeOptions) {
	if r == nil {
		return
	}

	offset := r.Request.Len()
	r.Request.Serialize(buff[:offset], options)
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
	if options >= base.SerializeSemiMutable {
		for _, alloc := range r.AllocationTrail {
			buff[offset] = byte(alloc)
			offset++
		}
	}
}

type SetupFailureInfo struct {
	NodeIndex int
	Message   string
}
