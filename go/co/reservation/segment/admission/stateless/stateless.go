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

package stateless

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

// StatelessAdmission can admit a segment reservation without any state other than the DB.
type StatelessAdmission struct {
	Caps  base.Capacities // aka capacity matrix
	Delta float64         // fraction of free BW that can be reserved in one request
}

var _ admission.Admitter = (*StatelessAdmission)(nil)

func (a *StatelessAdmission) Capacities() base.Capacities {
	return a.Caps
}

// AdmitRsv admits a segment reservation. The request will be modified with the allowed and
// maximum bandwidths if they were computed. It can also return an error that must be checked.
func (a *StatelessAdmission) AdmitRsv(ctx context.Context, x backend.ColibriStorage,
	req *segment.SetupReq) error {

	avail, err := a.availableBW(ctx, x, *req)
	if err != nil {
		return serrors.WrapStr("cannot compute available bandwidth", err, "segment_id", req.ID)
	}
	ideal, err := a.idealBW(ctx, x, *req)
	if err != nil {
		return serrors.WrapStr("cannot compute ideal bandwidth", err, "segment_id", req.ID)
	}
	maxAlloc := reservation.BWClsFromBW(minBW(avail, ideal))
	bead := reservation.AllocationBead{
		AllocBW: reservation.MinBWCls(maxAlloc, req.MaxBW),
		MaxBW:   maxAlloc,
	}
	req.AllocTrail = append(req.AllocTrail, bead)
	if maxAlloc < req.MinBW {
		return serrors.New("admission denied", "maxalloc", maxAlloc, "minbw", req.MinBW,
			"segment_id", req.ID.String())
	}
	return nil
}

func (a *StatelessAdmission) availableBW(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq) (uint64, error) {

	ingress := req.Ingress()
	sameIngress, err := x.GetSegmentRsvsFromIFPair(ctx, &ingress, nil)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using ingress", err,
			"ingress", ingress)
	}
	egress := req.Egress()
	sameEgress, err := x.GetSegmentRsvsFromIFPair(ctx, nil, &egress)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using egress", err,
			"egress", egress)
	}
	bwIngress := sumMaxBlockedBW(sameIngress, req.ID)
	freeIngress := a.Caps.CapacityIngress(ingress) - bwIngress
	bwEgress := sumMaxBlockedBW(sameEgress, req.ID)
	freeEgress := a.Caps.CapacityEgress(egress) - bwEgress
	// `free` excludes the BW from an existing reservation if its ID equals the request's ID
	free := float64(minBW(freeIngress, freeEgress))
	return uint64(free * a.Delta), nil
}

func (a *StatelessAdmission) idealBW(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq) (uint64, error) {

	tubeRatio, err := a.tubeRatio(ctx, x, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute tube ratio", err)
	}
	linkRatio, err := a.linkRatio(ctx, x, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute link ratio", err)
	}
	cap := float64(a.Caps.CapacityEgress(req.Egress()))
	return uint64(cap * tubeRatio * linkRatio), nil
}

func (a *StatelessAdmission) tubeRatio(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq) (float64, error) {

	transitDemand, err := a.transitDemand(ctx, x, req.Ingress(), req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute tube ratio", err)
	}
	capIn := a.Caps.CapacityIngress(req.Ingress())
	numerator := minBW(capIn, transitDemand)

	var sum uint64
	for _, in := range a.Caps.IngressInterfaces() {
		dem, err := a.transitDemand(ctx, x, in, req)
		if err != nil {
			return 0, serrors.WrapStr("cannot compute tube ratio", err)
		}
		sum += minBW(a.Caps.CapacityIngress(in), dem)
	}
	if sum == 0 || numerator == 0 {
		return 1, nil
	}
	return float64(numerator) / float64(sum), nil
}

func (a *StatelessAdmission) linkRatio(ctx context.Context, x backend.ColibriStorage,
	req segment.SetupReq) (float64, error) {

	rsvs, err := x.GetAllSegmentRsvs(ctx)
	if err != nil {
		return 0, serrors.WrapStr("computing transit demand failed", err)
	}
	grouped := groupRsvsBySource(rsvs)
	if _, found := grouped[req.ID.ASID]; !found {
		// because srcAlloc needs to be called w/ the source for the request, and in the
		// DB there were none, add a group with that source and 0 reservations from the DB:
		grouped[req.ID.ASID] = make([]*segment.Reservation, 0)
	}

	egScalFctr := a.egScalFctr(grouped[req.ID.ASID], req.Egress(), req)
	numerator := egScalFctr * float64(req.PrevBW())

	var denom float64
	for src, rsvs := range grouped {
		egScalFctr = a.egScalFctr(rsvs, req.Egress(), req)
		srcAlloc := a.srcAlloc(rsvs, src, req.Ingress(), req.Egress(), req)
		denom += egScalFctr * float64(srcAlloc)
	}
	if denom == 0 {
		return 1, nil
	}
	return numerator / denom, nil
}

// transitDemand computes the transit demand from ingress to req.Egress .
func (a *StatelessAdmission) transitDemand(ctx context.Context, x backend.ColibriStorage,
	ingress uint16, req segment.SetupReq) (uint64, error) {

	rsvs, err := x.GetAllSegmentRsvs(ctx)
	if err != nil {
		return 0, serrors.WrapStr("computing transit demand failed", err)
	}
	grouped := groupRsvsBySource(rsvs)
	var sum uint64
	for _, rsvs := range grouped {
		dem := a.adjSrcDem(rsvs, ingress, req.Egress(), req)
		sum += dem
	}
	return sum, nil
}

// adjSrcDem computes the adjusted source demand.
// Parameter `rsvs` is all the reservations with the same source.
// There is no need for a source parameter, as it's not used.
func (a *StatelessAdmission) adjSrcDem(rsvs []*segment.Reservation, ingress, egress uint16,
	req segment.SetupReq) uint64 {

	scalFctr := math.Min(a.inScalFctr(rsvs, ingress, req), a.egScalFctr(rsvs, egress, req))
	srcDem := a.srcDem(rsvs, ingress, egress, req)
	return uint64(scalFctr * float64(srcDem))
}

// inScalFctr takes rsvs as all the reservations with the same source
func (a *StatelessAdmission) inScalFctr(rsvs []*segment.Reservation, ingress uint16,
	req segment.SetupReq) float64 {

	capIn := a.Caps.CapacityIngress(ingress)
	inDem := a.inDem(rsvs, ingress, req)
	if inDem == 0 {
		return 1
	}
	return float64(minBW(capIn, inDem)) / float64(inDem)
}

// egScalFctr takes rsvs as all the reservations with the same source
func (a *StatelessAdmission) egScalFctr(rsvs []*segment.Reservation, egress uint16,
	req segment.SetupReq) float64 {

	capEg := a.Caps.CapacityEgress(egress)
	egDem := a.egDem(rsvs, egress, req)
	if egDem == 0 {
		return 1
	}
	return float64(minBW(capEg, egDem)) / float64(egDem)
}

func (a *StatelessAdmission) inDem(rsvs []*segment.Reservation, ingress uint16,
	req segment.SetupReq) uint64 {

	var inDem uint64
	for _, eg := range a.Caps.EgressInterfaces() {
		inDem += a.srcDem(rsvs, ingress, eg, req)
	}
	return inDem
}

func (a *StatelessAdmission) egDem(rsvs []*segment.Reservation, egress uint16,
	req segment.SetupReq) uint64 {

	var egDem uint64
	for _, in := range a.Caps.IngressInterfaces() {
		egDem += a.srcDem(rsvs, in, egress, req)
	}
	return egDem
}

// srcDem computes the source demand. Parameter `rsvs` are all reservations with same source.
func (a *StatelessAdmission) srcDem(rsvs []*segment.Reservation, ingress, egress uint16,
	req segment.SetupReq) uint64 {

	capIn := a.Caps.CapacityIngress(ingress)
	capEg := a.Caps.CapacityEgress(req.Egress())
	var srcDem uint64
	for _, r := range rsvs {
		if r.Ingress() == ingress && r.Egress() == egress && !r.ID.Equal(&req.ID) {
			capReqDem := minBW(capIn, capEg, a.reqDem(*r, req))
			srcDem += capReqDem
		}
	}
	// lastly, add the request demand from the request itself
	if len(rsvs) > 0 && req.ID.ASID == rsvs[0].ID.ASID &&
		req.Ingress() == ingress && req.Egress() == egress {

		capReqDem := minBW(capIn, capEg, req.MaxBW.ToKbps())
		srcDem += capReqDem
	}
	return srcDem
}

func (a *StatelessAdmission) reqDem(r segment.Reservation, req segment.SetupReq) uint64 {
	var bw uint64
	if r.ID.Equal(&req.ID) {
		bw = req.MaxBW.ToKbps()
	} else {
		bw = r.MaxRequestedBW()
	}
	return bw
}

// srcAlloc computes how much bandwidth is allocated between ingress and egress, for
// a given source `source`. All reservations in `rsvs` are from `source`.
func (a *StatelessAdmission) srcAlloc(rsvs []*segment.Reservation, source addr.AS,
	ingress, egress uint16, req segment.SetupReq) uint64 {

	var sum uint64
	for _, r := range rsvs {
		if r.Ingress() == ingress && r.Egress() == egress {
			if !r.ID.Equal(&req.ID) {
				sum += r.MaxBlockedBW()
			}
		}

	}
	if source == req.ID.ASID {
		sum += req.PrevBW()
	}
	return sum
}

// sumMaxBlockedBW adds up all the max blocked bandwidth by the reservation, for all reservations,
// iff they don't have the same ID as "excludeThisRsv".
func sumMaxBlockedBW(rsvs []*segment.Reservation, excludeThisRsv reservation.ID) uint64 {
	var total uint64
	for _, r := range rsvs {
		if !r.ID.Equal(&excludeThisRsv) {
			total += r.MaxBlockedBW()
		}
	}
	return total
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

func groupRsvsBySource(rsvs []*segment.Reservation) map[addr.AS][]*segment.Reservation {
	grouped := make(map[addr.AS][]*segment.Reservation)
	for _, rsv := range rsvs {
		source := rsv.ID.ASID
		grouped[source] = append(grouped[source], rsv)
	}
	return grouped
}
