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

package stateful

import (
	"context"
	"math"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/segment/admission"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// StatefulAdmission can admit a segment reservation without any state other than the DB.
// TODO(juagargi) the stateful functions need to be called from the delete functions in the DB.
type StatefulAdmission struct {
	Caps  base.Capacities // aka capacity matrix
	Delta float64         // fraction of free BW that can be reserved in one request
}

var _ admission.Admitter = (*StatefulAdmission)(nil)

func (a *StatefulAdmission) Capacities() base.Capacities {
	return a.Caps
}

// AdmitRsv admits a segment reservation. The request will be modified with the allowed and
// maximum bandwidths if they were computed. It can also return an error that must be checked.
func (a *StatefulAdmission) AdmitRsv(ctx context.Context, x backend.ColibriStorage,
	req *segment.SetupReq) error {

	pad := &ScratchPad{}
	avail, err := a.availableBW(ctx, x, *req)
	if err != nil {
		return serrors.WrapStr("cannot compute reservation admission", err, "request_id", req.ID)
	}
	ideal, err := a.idealBW(ctx, x, *req, pad)
	if err != nil {
		return serrors.WrapStr("cannot compute reservation admission", err, "request_id", req.ID)
	}
	maxAlloc := reservation.BWClsFromBW(minBW(avail, ideal))
	bead := reservation.AllocationBead{
		AllocBW: reservation.MinBWCls(maxAlloc, req.MaxBW),
		MaxBW:   maxAlloc,
	}
	req.AllocTrail = append(req.AllocTrail, bead)

	// update the scratch pad's source alloc with bead.AllocBW iff there is no resv. in
	// the DB with the same ID and higher blocked BW. Use the higher BW otherwise
	pad.SrcAlloc, err = a.updateSrcAllocWithAdmittedRequest(ctx, x, *req, bead.AllocBW.ToKbps())
	if err != nil {
		return serrors.WrapStr("cannot compute reservation admission", err, "request_id", req.ID)
	}

	// and fail the admission if the minimum requested was higher
	if maxAlloc < req.MinBW {
		return serrors.New("admission denied", "maxalloc", maxAlloc, "minbw", req.MinBW,
			"segment_id", req.ID.String())
	}

	// update stateful tables with the scratchpad
	if err = x.PersistTransitDem(ctx, req.Ingress(), req.Egress(), pad.TransitDem); err != nil {
		return serrors.WrapStr("cannot persist transit demand", err)
	}
	if err = x.PersistTransitAlloc(ctx, req.Ingress(), req.Egress(), pad.TransitAlloc); err != nil {
		return serrors.WrapStr("cannot persist transit alloc", err)
	}
	if err = x.PersistSourceState(ctx, req.ID.ASID, req.Ingress(), req.Egress(),
		pad.SrcDem, pad.SrcAlloc); err != nil {
		return serrors.WrapStr("cannot persist source state", err)
	}
	if err = x.PersistInDemand(ctx, req.ID.ASID, req.Ingress(), pad.InDemand); err != nil {
		return serrors.WrapStr("cannot persist ingress demand", err)
	}
	if err = x.PersistEgDemand(ctx, req.ID.ASID, req.Egress(), pad.EgDemand); err != nil {
		return serrors.WrapStr("cannot persist egress demand", err)
	}
	return nil
}

// ScratchPad stores the intermediate calculations that will be stored in
// the state tables in the DB (e.g. transit demand).
// Since reproducing these calculations in the DB is pointless, the DB expects calls
// to persist these stateful values individually.
type ScratchPad struct {
	TransitDem   uint64
	TransitAlloc uint64
	SrcDem       uint64
	SrcAlloc     uint64 // only known at the end of the admission
	InDemand     uint64
	EgDemand     uint64
}

func (a *StatefulAdmission) availableBW(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq) (uint64, error) {

	usedIngress, err := x.GetInterfaceUsageIngress(ctx, req.Ingress())
	if err != nil {
		return 0, serrors.WrapStr("computing available bw, used ingress failed", err)
	}
	usedEgress, err := x.GetInterfaceUsageEgress(ctx, req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing available bw, used egress failed", err)
	}
	excludeRsv, err := x.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return 0, serrors.WrapStr("computing available bw, get existing rsv failed", err)
	}
	if excludeRsv != nil {
		blocked := excludeRsv.MaxBlockedBW()
		if excludeRsv.Ingress() == req.Ingress() {
			usedIngress -= blocked
		}
		if excludeRsv.Egress() == req.Egress() {
			usedEgress -= blocked
		}
	}
	capIn := int64(a.Caps.CapacityIngress(req.Ingress()))
	capEg := int64(a.Caps.CapacityEgress(req.Egress()))
	freeIngress := uint64(maxSignedBW(0, capIn-int64(usedIngress)))
	freeEgress := uint64(maxSignedBW(0, capEg-int64(usedEgress)))
	free := float64(minBW(freeIngress, freeEgress))

	return uint64(free * a.Delta), nil
}

func (a *StatefulAdmission) idealBW(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq, pad *ScratchPad) (uint64, error) {

	tubeRatio, err := a.tubeRatio(ctx, x, req, pad)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute tube ratio", err)
	}
	linkRatio, err := a.linkRatio(ctx, x, req, pad)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute link ratio", err)
	}
	cap := float64(a.Caps.CapacityEgress(req.Egress()))
	return uint64(cap * tubeRatio * linkRatio), nil
}

func (a *StatefulAdmission) tubeRatio(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq, pad *ScratchPad) (float64, error) {

	transitDemand, err := a.transitDemand(ctx, x, req.Ingress(), req, pad)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute transit demand", err)
	}
	pad.TransitDem = transitDemand
	capIn := a.Caps.CapacityIngress(req.Ingress())
	numerator := minBW(capIn, transitDemand)
	sumTransits := numerator
	for _, in := range a.Caps.IngressInterfaces() {
		if in == req.Ingress() {
			continue
		}
		transitDem, err := a.transitDemand(ctx, x, in, req, pad)
		if err != nil {
			return 0, serrors.WrapStr("computing tube ratio failed", err)
		}

		sumTransits += minBW(a.Caps.CapacityIngress(in), transitDem)
	}
	return float64(numerator) / float64(sumTransits), nil
}

// linkRatio obtains the link ratio between req.Ingress and req.Egress.
// It avoids summing thru all sources by storing the previously computed sum
// and then adjusting it by subtracting the stored egScalFctr x srcAlloc and adding
// the computed egScalFctr x srcAlloc
func (a *StatefulAdmission) linkRatio(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq, pad *ScratchPad) (float64, error) {

	var denominator uint64
	// stored sum:
	storedSum, err := x.GetTransitAlloc(ctx, req.Ingress(), req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}
	denominator = storedSum

	// adjust by subtracting the stored egScalFctr x srcAlloc for this source:
	_, storedSrcAlloc, err := x.GetSourceState(ctx, req.ID.ASID, req.Ingress(), req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}
	storedEgDem, err := x.GetEgDemand(ctx, req.ID.ASID, req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}
	storedEgScalFctr := a.computeEgScalFctr(req.Egress(), storedEgDem)
	denominator -= uint64(storedEgScalFctr * float64(storedSrcAlloc))

	// adjust by adding the computed egScalFctr and srcAlloc
	egScalFctr, err := a.egScalFctr(ctx, x, req.ID.ASID, req.Egress(), req, pad)
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}
	prevBW := req.PrevBW()
	srcAlloc := storedSrcAlloc + prevBW
	rsv, err := x.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}
	if rsv != nil && rsv.Ingress() == req.Ingress() && rsv.Egress() == req.Egress() {
		// must subtract this reservation's blocked BW from srcAlloc, as it has
		// the ID of the request
		srcAlloc -= rsv.MaxBlockedBW()
	}
	// don't update pad.SrcAlloc as we don't know yet what will be the final allocated BW for req.
	denominator += uint64(egScalFctr * float64(srcAlloc))
	pad.TransitAlloc = denominator

	numerator := egScalFctr * float64(prevBW)

	ratio := numerator / float64(denominator)
	return ratio, nil
}

// transitDemand obtains the transit demand between req.Ingress and req.Egress
// by storing the previously computed transit demand, and then adjusting it
// by adding the difference between the computed adjusted source demand `adjSrcDem` using
// the request `req` and the one not using the request but only the reservations in the DB.
func (a *StatefulAdmission) transitDemand(ctx context.Context, x backend.ColibriStorage,
	ingress uint16, req segment.SetupReq, pad *ScratchPad) (uint64, error) {

	transit, err := x.GetTransitDem(ctx, ingress, req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing transit failed", err)
	}
	adjSrcDemDiff, err := a.adjSrcDemDifference(ctx, x, ingress, req, pad)
	if err != nil {
		return 0, serrors.WrapStr("computing transit failed", err)
	}
	return transit + uint64(adjSrcDemDiff), nil // casting to uint64 still subtracts if negative
}

// adjSrcDemDifference returns the difference between the stored adjSrcDem in DB and the
// computed one (temporal) using the request.
func (a *StatefulAdmission) adjSrcDemDifference(ctx context.Context, x backend.ColibriStorage,
	ingress uint16, req segment.SetupReq, pad *ScratchPad) (int64, error) {

	// stored:
	storedSrcDem, _, err := x.GetSourceState(ctx, req.ID.ASID, ingress, req.Egress())
	if err != nil {
		return 0, err
	}
	if storedSrcDem > 0 {
		inDem, err := x.GetInDemand(ctx, req.ID.ASID, ingress)
		if err != nil {
			return 0, err
		}
		egDem, err := x.GetEgDemand(ctx, req.ID.ASID, req.Egress())
		if err != nil {
			return 0, err
		}
		inScalFctr := a.computeInScalFctr(ingress, inDem)
		egScalFctr := a.computeEgScalFctr(req.Egress(), egDem)
		storedSrcDem = uint64(math.Min(inScalFctr, egScalFctr) * float64(storedSrcDem))
	}
	// computed
	srcDem, err := a.srcDem(ctx, x, req.ID.ASID, ingress, req.Egress(), req)
	if err != nil {
		return 0, err
	}
	var computedSrcDem uint64
	if srcDem > 0 {
		inScalFctr, err := a.inScalFctr(ctx, x, req.ID.ASID, ingress, req, pad)
		if err != nil {
			return 0, err
		}
		egScalFctr, err := a.egScalFctr(ctx, x, req.ID.ASID, req.Egress(), req, pad)
		if err != nil {
			return 0, err
		}
		computedSrcDem = uint64(math.Min(inScalFctr, egScalFctr) * float64(srcDem))
	}
	if ingress == req.Ingress() {
		pad.SrcDem = computedSrcDem // update srcDem for the request's interface pair
	}
	return int64(computedSrcDem - storedSrcDem), nil
}

// srcDem obtains the srcDem by storing the previously computed one, and adjusting
// the capped srcDem for the reservation with ID == req.ID:
// srcDem(src,in,eg) = stored_srcDem(src,in,eg)
//                   - capReqDem(req.ID) from DB [iff it is present in DB]
//                   + capped req.ID.MaxRequestedBW
func (a *StatefulAdmission) srcDem(ctx context.Context, x backend.ColibriStorage, source addr.AS,
	ingress, egress uint16, req segment.SetupReq) (uint64, error) {

	srcDem, _, err := x.GetSourceState(ctx, source, ingress, egress)
	if err != nil {
		return 0, serrors.WrapStr("computing src dem failed", err)
	}
	if ingress == req.Ingress() && egress == req.Egress() {
		capIn := a.Caps.CapacityIngress(ingress)
		capEg := a.Caps.CapacityEgress(egress)
		// subtract DB's capReqDem(req.ID)
		rsv, err := x.GetSegmentRsvFromID(ctx, &req.ID)
		if err != nil {
			return 0, serrors.WrapStr("computing src dem failed", err)
		}
		if rsv != nil {
			srcDem -= minBW(capIn, capEg, rsv.MaxRequestedBW())
		}
		// add capReqDem
		srcDem += minBW(capIn, capEg, req.MaxBW.ToKbps())
	}
	return srcDem, nil
}

func (a *StatefulAdmission) computeInScalFctr(ingress uint16, inDem uint64) float64 {
	if inDem == 0 {
		return 1
	}
	return float64(minBW(inDem, a.Caps.CapacityIngress(ingress))) / float64(inDem)
}

func (a *StatefulAdmission) computeEgScalFctr(egress uint16, egDem uint64) float64 {
	if egDem == 0 {
		return 1
	}
	return float64(minBW(egDem, a.Caps.CapacityEgress(egress))) / float64(egDem)
}

func (a *StatefulAdmission) inScalFctr(ctx context.Context, x backend.ColibriStorage,
	source addr.AS, ingress uint16, req segment.SetupReq, pad *ScratchPad) (float64, error) {

	dem, err := x.GetInDemand(ctx, source, ingress)
	if err != nil {
		return 0, serrors.WrapStr("computing in scale factor", err)
	}
	// subtract the srcDem(src,in,req.Eg) added in the past
	srcDem, _, err := x.GetSourceState(ctx, source, ingress, req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing in scale factor failed", err)
	}
	dem -= srcDem
	// add the srcDem(src,in,req.Eg) computed now
	srcDem, err = a.srcDem(ctx, x, source, ingress, req.Egress(), req)
	if err != nil {
		return 0, serrors.WrapStr("computing in scale factor failed", err)
	}
	dem += srcDem
	pad.InDemand = dem

	return a.computeInScalFctr(ingress, dem), nil
}

func (a *StatefulAdmission) egScalFctr(ctx context.Context, x backend.ColibriStorage,
	source addr.AS, egress uint16, req segment.SetupReq, pad *ScratchPad) (float64, error) {

	dem, err := x.GetEgDemand(ctx, source, egress)
	if err != nil {
		return 0, serrors.WrapStr("computing eg scale factor", err)
	}
	// subtract the srcDem(src,req.In,eg) added in the past
	srcDem, _, err := x.GetSourceState(ctx, source, req.Ingress(), egress)
	if err != nil {
		return 0, serrors.WrapStr("computing eg scale factor failed", err)
	}
	dem -= srcDem
	// add the srcDem(src,req.In,eg) computed now
	srcDem, err = a.srcDem(ctx, x, source, req.Ingress(), egress, req)
	if err != nil {
		return 0, serrors.WrapStr("computing eg scale factor failed", err)
	}
	dem += srcDem
	pad.EgDemand = dem

	return a.computeEgScalFctr(egress, dem), nil
}

// updateSrcAllocWithAdmittedRequest returns the new srcAlloc using the allocated bandwidth for
// the request, or the max blocked bandwidth from a reservation with the same ID, if greater.
func (a *StatefulAdmission) updateSrcAllocWithAdmittedRequest(ctx context.Context,
	x backend.ColibriStorage, req segment.SetupReq, allocBW uint64) (uint64, error) {

	// previous src alloc:
	_, srcAlloc, err := x.GetSourceState(ctx, req.ID.ASID, req.Ingress(), req.Egress())
	if err != nil {
		return 0, serrors.WrapStr("computing updated src alloc", err)
	}

	// any reservation with the same ID?
	rsv, err := x.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return 0, serrors.WrapStr("computing link ratio failed", err)
	}

	var oldBlocked uint64
	newToBlock := allocBW

	if rsv != nil && rsv.Ingress() == req.Ingress() && rsv.Egress() == req.Egress() {
		blocked := rsv.MaxBlockedBW()
		if blocked < allocBW {
			oldBlocked = blocked // from existing reservation with same ID
		} else {
			newToBlock = 0
		}
	}
	// remove old one, add new one
	srcAlloc += (newToBlock - oldBlocked)
	return srcAlloc, nil
}

func minBW(a uint64, bws ...uint64) uint64 {
	min := a
	for _, bw := range bws {
		if bw < min {
			min = bw
		}
	}
	return min
}

func maxSignedBW(a int64, bws ...int64) int64 {
	max := a
	for _, bw := range bws {
		if bw > max {
			max = bw
		}
	}
	return max
}
