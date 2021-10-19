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
	"net"
	"sync"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SetupReq is an e2e setup/renewal request, that has been so far accepted.
type SetupReq struct {
	base.Request
	SrcIA                  addr.IA // necessary to compute the MACs during admission
	SrcHost                net.IP
	DstIA                  addr.IA
	DstHost                net.IP
	RequestedBW            col.BWCls
	SegmentRsvs            []col.ID
	CurrentSegmentRsvIndex int // index in SegmentRsv above. Transfer nodes use the first segment
	AllocationTrail        []col.BWCls
	isTransferOnce         sync.Once
	isTransfer             bool
}

type SetupFailureInfo struct {
	NodeIndex int
	Message   string
}

func (r *SetupReq) Validate() error {
	var err error
	if r.RequestPathNeedsSteps() {
		err = r.Request.ValidateIgnorePath()
	} else {
		err = r.Request.Validate()
	}
	if err != nil {
		return err
	}

	if !r.ID.IsE2EID() {
		return serrors.New("non e2e AS id in request", "asid", r.ID.ASID)
	}
	if len(r.SegmentRsvs) == 0 || len(r.SegmentRsvs) > 3 {
		return serrors.New("invalid number of segment reservations for an e2e request",
			"count", len(r.SegmentRsvs))
	}
	if r.SrcIA.IsZero() || r.SrcHost == nil || r.SrcHost.IsUnspecified() ||
		r.DstIA.IsZero() || r.DstHost == nil || r.DstHost.IsUnspecified() {

		return serrors.New("empty fields not allowed", "src_ia", r.SrcIA, "src_host", r.SrcHost,
			"dst_ia", r.DstIA, "dst_host", r.DstHost)
	}
	return nil
}

// RequestPathNeedsSteps indicates a request that will need to extend its base.Request.Path.
// This happens everytime the AS is at the end of the path but there are still segments
// pending to transit.
func (r *SetupReq) RequestPathNeedsSteps() bool {
	return len(r.Path.Steps) == 0 ||
		(r.IsLastAS() && r.CurrentSegmentRsvIndex < len(r.SegmentRsvs)-1)
}

// IsTransfer indicates if the node where this being processed is a transfer node or not.
// A transfer node is that node that stitches two segment reservations when creating a new
// E2E reservation. It needs at least two segments and to be present right at the end of
// the current segment. The first or last node in the full request path is never a transfer node.
func (r *SetupReq) IsTransfer() bool {
	r.isTransferOnce.Do(func() {
		if len(r.SegmentRsvs) > 1 && r.CurrentSegmentRsvIndex < len(r.SegmentRsvs)-1 &&
			r.Path.CurrentStep > 0 && r.Path.CurrentStep == len(r.Path.Steps)-1 {
			r.isTransfer = true
		} else {
			r.isTransfer = false
		}
	})
	return r.isTransfer
}

// SegmentRsvIDsForThisAS returns the segment reservation ID this AS belongs to. Iff this
// AS is a transfer AS (stitching point), there will be two reservation IDs returned, in the
// order of traversal.
func (r *SetupReq) SegmentRsvIDsForThisAS() []col.ID {
	indices := make([]col.ID, 1, 2)
	indices[0] = r.SegmentRsvs[r.CurrentSegmentRsvIndex]
	if r.IsTransfer() {
		indices = append(indices, r.SegmentRsvs[r.CurrentSegmentRsvIndex+1])
	}
	return indices
}
