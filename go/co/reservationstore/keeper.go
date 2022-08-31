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

package reservationstore

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/conf"
	seg "github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/serrors"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/snet"
)

// This file defines the entries that the keeper looks after.
// Per entry, the keeper will setup new reservations:
// - look for compatible reservations in our store; these will be renewed. If not enough, go on.
// - using all the compatible paths to destination:
// 	 - emit as many requests as needed to fill minActiveRsvs.
//   - wait for success or keep on emitting requests, until he have enough successful minActiveRsvs.
//
// Per entry, the keeper will renew all the associated reservations.
// - renew each reservation
// - if failure, remove it from the active reservations association.
// - the next pass of the keeper will check if we have enough active reservations.
//
// The keeper always knows the nearest point in time when a reservation will expire.

// sleepAtLeast is the time duration that the keeper will sleep at a minimum, even
// if it's called very frequently.
const sleepAtLeast = 4 * time.Second

const sleepAtMost = 5 * time.Minute

// min validity in the future for the reservations when checking their compliance,
// the bigger the value, the more probable it is not to break continuity.
// Typically this value would be twice the max. sleep period, to ensure no index would
// expire while the keeper is sleeping.
const minDuration = 2 * sleepAtMost

// min validity of new indices/reservations. The bigger the value, the longer a single index
// can be used. Too big a value could produce errors in the admission for some ASes.
// This value would typically be equal to twice minDuration.
const newIndexMinDuration = 2 * minDuration

type keeper struct {
	sleepUntil time.Time // nothing to do in the keeper until this time
	manager    Manager
	entries    []entry
	deletemes  map[addr.IA][]requirementsDeleteme
}

type entry struct {
	conf requirements
	rsv  *seg.Reservation
}

func (e *entry) PrepareSetupRequest(now, expTime time.Time, localAS addr.AS,
	p snet.Path) *seg.SetupReq {

	steps, err := base.StepsFromSnet(p)
	if err != nil {
		log.Info("error in SCION path, cannot convert to steps", "err", err, "path", p)
		panic(err)
	}
	rawPath, err := base.PathFromDataplanePath(p.Dataplane())
	if err != nil {
		log.Info("error in SCION path, cannot get dataplane", "err", err, "path", p)
	}
	id, _ := reservation.NewID(localAS, make([]byte, reservation.IDSuffixSegLen))
	return &seg.SetupReq{
		Request:        *base.NewRequest(now, id, 0, len(steps)),
		ExpirationTime: expTime,
		PathType:       e.conf.pathType,
		MinBW:          e.conf.minBW,
		MaxBW:          e.conf.maxBW,
		SplitCls:       e.conf.splitCls,
		PathProps:      e.conf.endProps,
		AllocTrail:     reservation.AllocationBeads{},
		Steps:          steps,
		RawPath:        rawPath,
	}
}

func (e *entry) PrepareRenewalRequest(now, expTime time.Time) *seg.SetupReq {
	return &seg.SetupReq{
		Request: *base.NewRequest(
			now, &e.rsv.ID, e.rsv.NextIndexToRenew(), len(e.rsv.Steps)),
		ExpirationTime: expTime,
		PathType:       e.conf.pathType,
		MinBW:          e.conf.minBW,
		MaxBW:          e.conf.maxBW,
		SplitCls:       e.rsv.TrafficSplit,
		PathProps:      e.rsv.PathEndProps,
		AllocTrail:     reservation.AllocationBeads{},
		Steps:          e.rsv.Steps.Copy(),
		RawPath:        e.rsv.RawPath,
		Reservation:    e.rsv,
	}
}

func NewKeeper(ctx context.Context, manager Manager, conf *conf.Reservations) (
	*keeper, error) {

	// load configuration
	reqs, err := parseInitial(conf)
	if err != nil {
		return nil, err
	}
	// get existing reservations
	// TODO(juagargi) cleanup expired indices before reading reservations
	rsvs, err := manager.GetReservationsAtSource(ctx)
	if err != nil {
		return nil, err
	}

	// load configuration
	entries, err := parseInitialDeleteme(conf)
	if err != nil {
		return nil, err
	}
	rsvsCount := 0
	for _, r := range entries {
		rsvsCount += len(r)
	}
	log.Debug("colibri keeper", "reservations", rsvsCount)
	return &keeper{
		sleepUntil: time.Now().Add(-time.Nanosecond),
		manager:    manager,
		entries:    matchRsvsWithConfiguration(rsvs, reqs),
		deletemes:  entries,
	}, nil
}

// OneShot keeps all reservations healthy. Those that need renewal are renewed, those
// that still have no reservation ID for its config will request a new one.
// The function returns the time when it should be called next.
func (k *keeper) OneShot(ctx context.Context) (time.Time, error) {
	wakeupAtLatest := k.manager.Now().Add(sleepAtMost)
	wg := sync.WaitGroup{}
	times := make([]time.Time, len(k.entries))
	errs := make(serrors.List, len(k.entries))
	wg.Add(len(k.entries))
	for i, e := range k.entries {
		i, e := i, e
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			times[i], errs[i] = k.keepReservation(ctx, &e)
		}()
	}
	wg.Wait()
	for _, t := range times {
		if t.Before(wakeupAtLatest) {
			wakeupAtLatest = t
		}
	}
	if wakeupAtLatest.Sub(k.manager.Now()) < sleepAtLeast {
		wakeupAtLatest = k.manager.Now().Add(sleepAtLeast)
	}
	return wakeupAtLatest, errs.Coalesce()
}

// OneShotDeleteme returns the time when it expects to be called again. Before this time it has
// nothing to do.
func (k *keeper) OneShotDeleteme(ctx context.Context) (time.Time, error) {
	wg := sync.WaitGroup{}
	wg.Add(len(k.deletemes))
	wakeupTimes := make(chan time.Time, len(k.deletemes))
	for dst, entries := range k.deletemes {
		dst, entries := dst, entries
		go func(c chan time.Time) {
			defer log.HandlePanic()
			defer wg.Done()
			scionPaths, err := k.manager.PathsTo(ctx, dst)
			if err != nil {
				log.Error("keeping the reservations, querying paths", "err", err)
			}
			wakeup, err := k.keepDestinationDeleteme(ctx, dst, entries, scionPaths)
			if err != nil {
				log.Error("keeping the reservations", "err", err)
			}
			c <- wakeup
		}(wakeupTimes)
	}
	wg.Wait()
	close(wakeupTimes)
	earliest := k.manager.Now().Add(sleepAtMost)
	for wakeup := range wakeupTimes {
		if wakeup.Before(earliest) {
			earliest = wakeup
		}
	}
	if earliest.Sub(k.manager.Now()) < sleepAtLeast {
		earliest = k.manager.Now().Add(sleepAtLeast)
	}
	return earliest, nil
}

// keepReservation will ensure that the reservation exists or a request is created.
func (k *keeper) keepReservation(ctx context.Context, e *entry) (time.Time, error) {
	now := k.manager.Now()
	var err error
	if e.rsv == nil {
		e.rsv, err = k.askNewReservation(ctx, e)
	} else {
		switch compliance(e, k.manager.Now().Add(minDuration)) {
		case Compliant:
		case NeedsActivation:
			err = k.activateIndex(ctx, e.rsv) // deleteme modify signature
		case NeedsIndices:
			err = k.askNewIndices(ctx, e)
		}
	}
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(newIndexMinDuration), nil
}

// matchRsvsWithConfiguration matches existing reservations with configuration.
// It returns the appropriate entries to manage from the keeper.
// Those entries without a reservation ID must obtain a new reservation;
// those with a reservation ID will need index activation, etc.
func matchRsvsWithConfiguration(rsvs []*seg.Reservation, conf []requirements) []entry {
	// greedy strategy: for each reservation try to match it with the first compatible configuration
	entries := make([]entry, 0)
	for _, r := range rsvs {
		i := findCompatibleConfiguration(r, conf)
		if i < 0 {
			continue
		}
		entries = append(entries, entry{
			conf: conf[i],
			rsv:  r,
		})
		// one conf. is matched against this r; remove that entry from the pool
		conf = append(conf[0:i], conf[i:len(conf)-1]...)
	}
	for _, c := range conf {
		entries = append(entries, entry{
			conf: c,
		})
	}
	return entries
}

// findCompatibleConfiguration finds the first compatible configuration with the reservation.
// It returns the index of the configuration in the slice, or -1 if no valid one is found.
func findCompatibleConfiguration(r *seg.Reservation, conf []requirements) int {
	for i, c := range conf {
		switch {
		case r.Steps.DstIA() != c.dst:
			continue
		case r.PathType != c.pathType:
			continue
		case r.TrafficSplit != c.splitCls:
			continue
		case r.PathEndProps != c.endProps:
			continue
		case !c.predicate.EvalInterfaces(r.Steps.Interfaces()):
			continue
		}
		idxs := r.Indices.Filter(seg.ByMinBW(c.minBW), seg.ByMaxBW(c.maxBW))
		if len(idxs) == 0 {
			continue
		}
		return i
	}
	return -1
}

// keepDestinationDeleteme will ensure that all reservations for dstIA exist and are compliant.
// It returns the time until there is nothing to do for these reservations.
func (k *keeper) keepDestinationDeleteme(ctx context.Context, dstIA addr.IA, entries []requirementsDeleteme,
	paths []snet.Path) (time.Time, error) {

	// get reservations once and pass them along.
	rsvs, err := k.manager.GetReservationsAtSourceDeleteme(ctx, dstIA)
	if err != nil {
		return time.Time{}, err
	}
	// setup new reservations
	sleepUntil, err := k.setupsPerDestination(ctx, dstIA, entries, paths, rsvs)
	if err != nil {
		return sleepUntil, serrors.WrapStr("keeping destination", err, "dst", dstIA)
	}
	return sleepUntil, nil
}

// setupsPerDestination processes all entries for a given IA sequentially, to avoid
// reservation racing. It creates the setup requests and later sends them.
// Returns the time until which there is nothing to do for these reservations.
func (k *keeper) setupsPerDestination(ctx context.Context, dstIA addr.IA, entries []requirementsDeleteme,
	paths []snet.Path, currentRsvs []*seg.Reservation) (time.Time, error) {

	now := k.manager.Now()
	wakeupTime := now.Add(sleepAtMost)
	errors := make(serrors.List, 0)
	for i, entry := range entries {
		// filter reservations
		atLeastUntil := k.manager.Now().Add(minDuration)
		compliantRsvs, needActivation, needIndices, notCompliant :=
			entry.SplitByCompliance(currentRsvs, atLeastUntil)

		log.Debug("colibri keeper, reservations by compliance", "ia", dstIA.String(),
			"i/total", fmt.Sprintf("%d/%d", i+1, len(entries)),
			"compliant", printRsvs(compliantRsvs), "need_activation", printRsvs(needActivation),
			"need_indices", printRsvs(needIndices), "never", printRsvs(notCompliant))

		// activation:
		if err := k.activateIndices(ctx, needActivation); err != nil {
			errors = append(errors, err)
			continue
		}
		expirationNewIndices := now.Add(newIndexMinDuration)
		// new indices:
		err := k.askNewIndicesDeleteme(ctx, needIndices, dstIA, entry, expirationNewIndices)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		// totally new reservations:
		requestCount := entry.minActiveRsvs -
			len(compliantRsvs) - len(needActivation) - len(needIndices)
		if requestCount < 0 {
			requestCount = 0
		}
		_, err = k.askNewReservations(ctx, requestCount,
			dstIA, entry, paths, expirationNewIndices)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		// the needIndices and new reservations are good for newIndexMinDuration
		if expirationNewIndices.Before(wakeupTime) && (len(needIndices) > 0 || requestCount > 0) {
			wakeupTime = expirationNewIndices
		}
		// we don't know yet when reservations from compliantRsvs or needActivation expire
		for _, rsv := range append(compliantRsvs, needActivation...) {
			if rsv.ActiveIndex().Expiration.Before(wakeupTime) {
				wakeupTime = rsv.ActiveIndex().Expiration
			}
		}
	}
	if len(errors) > 0 {
		return time.Time{}, errors.ToError()
	}
	return wakeupTime, nil
}

// activateIndices expects reservations that have a confirmed index that can be activated.
func (k *keeper) activateIndices(ctx context.Context, rsvs []*seg.Reservation) error {
	reqs := make([]*base.Request, len(rsvs))
	stepsCollection := make([]base.PathSteps, len(rsvs))
	paths := make([]slayerspath.Path, len(rsvs))
	for i, rsv := range rsvs {
		index := rsv.NextIndexToActivate()
		if index == nil {
			return serrors.New("request to activate, but no index suitable", "id", rsv.ID,
				"indices", rsv.Indices.String())
		}
		reqs[i] = base.NewRequest(k.manager.Now(), &rsv.ID, index.Idx, len(rsv.Steps.Copy()))
		stepsCollection[i] = rsv.Steps.Copy()
		paths[i] = rsv.RawPath
	}
	errs := filterEmptyErrors(k.manager.ActivateManyRequest(ctx, reqs, stepsCollection, paths))
	if len(errs) > 0 {
		log.Info("errors while activating rsvs", "errs", errs)
		return serrors.New("errors in activation")
	}
	return nil
}

func (k *keeper) activateIndex(ctx context.Context, r *seg.Reservation) error {
	req := base.NewRequest(k.manager.Now(), &r.ID, r.NextIndexToActivate().Idx, len(r.Steps))
	return k.manager.ActivateRequest(ctx, req, r.Steps.Copy(), r.RawPath)
}

// askNewIndicesDeleteme will prepare requests based on existing reservations and ask for new indices.
func (k *keeper) askNewIndicesDeleteme(ctx context.Context, rsvs []*seg.Reservation, dstIA addr.IA,
	entry requirementsDeleteme, atLeastUntil time.Time) error {

	// TODO(juagargi) test this function (the indices as seen in requests should be active+1)
	if len(rsvs) > 0 {
		requests, err := entry.PrepareRenewalRequests(rsvs, k.manager.Now(), atLeastUntil)
		if err != nil {
			return serrors.WrapStr("cannot request new indices", err)
		}
		// this will block until successfully finished
		return k.requestNSuccessfulRsvs(ctx, dstIA, entry, requests, len(rsvs))
	}
	return nil
}

// askNewIndices requests a renewal
func (k *keeper) askNewIndices(ctx context.Context, e *entry) error {
	now := k.manager.Now()
	req := e.PrepareRenewalRequest(now, now.Add(newIndexMinDuration))
	return k.manager.SetupRequest(ctx, req)
}

func (k *keeper) askNewReservation(ctx context.Context, e *entry) (*seg.Reservation, error) {
	now := k.manager.Now()
	paths, err := k.manager.PathsTo(ctx, e.conf.dst)
	if err != nil {
		return nil, err
	}
	// try with each possible path
	paths = e.conf.predicate.Eval(paths)
	for _, p := range paths {
		req := e.PrepareSetupRequest(now, now.Add(newIndexMinDuration), k.manager.LocalIA().AS(), p)
		err := k.manager.SetupRequest(ctx, req)
		if err == nil {
			if req.Reservation == nil {
				panic("logic error, reservation after new request is empty")
			}
			return req.Reservation, nil
		}
		log.Info("error creating new reservation from best effort path", "path", p)
	}
	return nil, serrors.New("no more best effort paths to create reservation", "dst", e.conf.dst)
}

// askNewReservations creates new requests based on the paths and the entry and ensures
// that at least `requiredSuccesful` are successful.
func (k *keeper) askNewReservations(ctx context.Context, requiredSuccesful int, dstIA addr.IA,
	entry requirementsDeleteme, paths []snet.Path, expTime time.Time) ([]*seg.Reservation, error) {

	// TODO(juagargi) test this function (indices seen in requests should always be zero)
	if requiredSuccesful > 0 {
		requests, err := entry.PrepareSetupRequests(paths, k.manager.LocalIA().AS(),
			k.manager.Now(), expTime)
		if err != nil {
			return nil, serrors.WrapStr("cannot setup new reservations", err, "paths", paths)
		}

		// this will block until successfully finished
		err = k.requestNSuccessfulRsvs(ctx, dstIA, entry, requests, requiredSuccesful)
		if err != nil {
			return nil, err
		}
		rsvs := make([]*seg.Reservation, 0)
		for _, req := range requests {
			if req.Reservation != nil {
				rsvs = append(rsvs, req.Reservation)
			}
		}
		return rsvs, nil
	}
	return nil, nil
}

// requestNSuccessfulRsvs uses the manager to request reservations in parallel, until
// the pending count is reached, or there are no more available requests.
func (k *keeper) requestNSuccessfulRsvs(ctx context.Context, dstIA addr.IA, entry requirementsDeleteme,
	requests []*seg.SetupReq, pendingCount int) error {

	needActivation := make([]*base.Request, 0)
	needActivationSteps := make([]base.PathSteps, 0)
	needActivationPaths := make([]slayerspath.Path, 0)
	var setups []*seg.SetupReq
	for pendingCount > 0 && len(requests) > 0 {
		indices := entry.SelectRequests(requests, pendingCount)
		setups, requests = splitRequests(requests, indices)
		errs := k.manager.SetupManyRequest(ctx, setups)
		for i, req := range setups {
			if errs[i] == nil {
				needActivation = append(needActivation, base.NewRequest(k.manager.Now(), &req.ID,
					req.Index, len(req.Steps)))
				needActivationSteps = append(needActivationSteps, req.Steps)
				needActivationPaths = append(needActivationPaths, req.RawPath)
			}
		}
		errs = filterEmptyErrors(errs)
		if len(errs) > 0 {
			log.Info("errors while requesting reservations", "errs", errs)
		}
		pendingCount = pendingCount - len(setups) + len(errs)
	}
	if pendingCount > 0 {
		return serrors.New("could not request the minimum required of reservations",
			"dst", dstIA, "requests_len", len(requests))
	}
	errs := filterEmptyErrors(k.manager.ActivateManyRequest(
		ctx,
		needActivation,
		needActivationSteps,
		needActivationPaths,
	))
	if len(errs) > 0 {
		log.Info("errors while activating reservations", "errs", errs)
		return serrors.New("could not activate all reservations", "err_count", len(errs))
	}
	return nil
}

// requirements is a 1 to 1 association to a conf.ReservationEntry
type requirements struct {
	dst           addr.IA
	pathType      reservation.PathType
	predicate     *pathpol.Sequence
	minBW         reservation.BWCls
	maxBW         reservation.BWCls
	splitCls      reservation.SplitCls
	endProps      reservation.PathEndProps
	minActiveRsvs int
}

// deleteme
// requirementsDeleteme is a 1 to 1 association to a conf.ReservationEntry
type requirementsDeleteme struct {
	pathType      reservation.PathType
	predicate     *pathpol.Sequence
	minBW         reservation.BWCls
	maxBW         reservation.BWCls
	splitCls      reservation.SplitCls
	endProps      reservation.PathEndProps
	minActiveRsvs int
}

type Compliance int

const (
	// deleteme remove nevercompliant
	NeverCompliant  = Compliance(iota) // reservation values always out of compliance
	NeedsIndices                       // ask for a new index
	NeedsActivation                    // ask to activate index
	Compliant                          // already has an active compliant index
)

func (c Compliance) String() string {
	switch c {
	case NeverCompliant:
		return "NeverCompliant"
	case NeedsIndices:
		return "NeedsIndices"
	case NeedsActivation:
		return "NeedsActivation"
	case Compliant:
		return "Compliant"
	default:
		panic(fmt.Errorf("unknown value for compliance %d", c))
	}
}

// SplitByCompliance will split the reservations into three groups:
// compliant, needsActivation, needsIndices and not compliant, according to the requirements
// of this entry. For an explanation of compliance, see the type `Compliance`.
func (e *requirementsDeleteme) SplitByCompliance(rsvs []*seg.Reservation, atLeastUntil time.Time) (
	[]*seg.Reservation, []*seg.Reservation, []*seg.Reservation, []*seg.Reservation) {

	compliant := make([]*seg.Reservation, 0)
	needIndices := make([]*seg.Reservation, 0)
	needActivation := make([]*seg.Reservation, 0)
	neverCompliant := make([]*seg.Reservation, 0)
	for _, rsv := range rsvs {
		compliance := e.Compliance(rsv, atLeastUntil)
		switch compliance {
		case Compliant:
			compliant = append(compliant, rsv)
		case NeedsActivation:
			needActivation = append(needActivation, rsv)
		case NeedsIndices:
			needIndices = append(needIndices, rsv)
		case NeverCompliant:
			neverCompliant = append(neverCompliant, rsv)
		}
	}
	return compliant, needActivation, needIndices, neverCompliant
}

// PrepareSetupRequests creates new reservation requests compliant with the requirements.
// This function creates as many reservations requests as there are
// scion paths compatible with the requirements.
func (e *requirementsDeleteme) PrepareSetupRequests(paths []snet.Path,
	localAS addr.AS, now time.Time, expTime time.Time) ([]*seg.SetupReq, error) {

	// filter paths
	filtered := e.predicate.Eval(paths)
	requests := make([]*seg.SetupReq, len(filtered))
	// create setup requests
	for i, p := range filtered {
		steps, err := base.StepsFromSnet(p)
		if err != nil {
			return nil, err
		}
		// chop all hop fields except those to reach the next AS
		rawPath, err := base.ChoppedPathFromDataplane(p.Dataplane())
		if err != nil {
			return nil, err
		}

		id := reservation.ID{
			ASID:   localAS,
			Suffix: make([]byte, reservation.IDSuffixSegLen),
		}
		req := &seg.SetupReq{
			Request:        *base.NewRequest(now, &id, 0, len(steps)),
			ExpirationTime: expTime,
			// RLC:            rlc,
			PathType:    e.pathType,
			MinBW:       e.minBW,
			MaxBW:       e.maxBW,
			SplitCls:    e.splitCls,
			PathProps:   e.endProps,
			AllocTrail:  reservation.AllocationBeads{},
			Steps:       steps,
			CurrentStep: 0,
			RawPath:     rawPath,
		}
		requests[i] = req
		log.Debug("keeper prepared request", "id", req.ID, "dst", req.Steps.DstIA(),
			"path", req.Steps)
	}
	return requests, nil
}

func (e *requirementsDeleteme) PrepareRenewalRequests(rsvs []*seg.Reservation, now, expTime time.Time) (
	[]*seg.SetupReq, error) {

	requests := []*seg.SetupReq{}
	for _, rsv := range rsvs {
		if !e.predicate.EvalInterfaces(rsv.Steps.Interfaces()) {
			continue
		}
		req := &seg.SetupReq{
			Request: *base.NewRequest(now, &rsv.ID, rsv.NextIndexToRenew(),
				len(rsv.Steps)),
			ExpirationTime: expTime,
			// RLC:            e.RLC,
			PathType:    rsv.PathType,
			MinBW:       e.minBW,
			MaxBW:       e.maxBW,
			SplitCls:    rsv.TrafficSplit,
			PathProps:   rsv.PathEndProps,
			AllocTrail:  reservation.AllocationBeads{}, // at source
			Steps:       rsv.Steps,
			RawPath:     rsv.RawPath,
			Reservation: rsv,
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (e *requirementsDeleteme) SelectRequests(requests []*seg.SetupReq, n int) []int {
	if n > len(requests) {
		n = len(requests)
	}
	rand.Seed(time.Now().UnixNano()) // TODO(juagargi) select using better criteria
	return rand.Perm(n)
}

// Compliance checks the given reservation against the requirements and returns true if
// it satisfies them, plus the reservation is good at least until the time in `atLeastUntil`.
func (e requirementsDeleteme) Compliance(rsv *seg.Reservation, atLeastUntil time.Time) Compliance {
	switch {
	case rsv.PathType != e.pathType:
		return NeverCompliant
	case rsv.TrafficSplit != e.splitCls:
		return NeverCompliant
	case rsv.PathEndProps != e.endProps:
		return NeverCompliant
	case !e.predicate.EvalInterfaces(rsv.Steps.Interfaces()):
		return NeverCompliant
	}
	indices := rsv.Indices.Filter(
		seg.ByExpiration(atLeastUntil),
		seg.ByMinBW(e.minBW),
		seg.ByMaxBW(e.maxBW),
		seg.NotConfirmed(),
	)
	if len(indices) == 0 { // no valid index found
		return NeedsIndices
	}
	if len(indices.Filter(seg.NotSwitchableFrom(rsv.ActiveIndex()))) == 0 { // no active index
		return NeedsActivation
	}
	return Compliant
}

func compliance(e *entry, until time.Time) Compliance {
	idxs := e.rsv.Indices.Filter(
		seg.ByMinBW(e.conf.minBW),
		seg.ByMaxBW(e.conf.maxBW),
		seg.NotConfirmed(),
		seg.ByExpiration(until),
	)
	switch {
	case len(idxs) == 0:
		return NeedsIndices
	case len(idxs.Filter(seg.NotSwitchableFrom(e.rsv.ActiveIndex()))) == 0:
		return NeedsActivation
	default:
		return Compliant
	}
}

// splitRequests takes a slice of requests and indices, and returns two slices:
// first, those elements in the indices, in the exact order as specified in indices.
// second, all the other elements.
func splitRequests(requests []*seg.SetupReq, indices []int) (
	[]*seg.SetupReq, []*seg.SetupReq) {
	a := make([]*seg.SetupReq, len(indices))
	b := append(requests[:0:0], requests...)
	for i, idx := range indices {
		a[i] = requests[idx]
		b[idx] = b[len(b)-i-1]
	}
	return a, b[:len(b)-len(a)]
}

func parseInitial(conf *conf.Reservations) ([]requirements, error) {
	if conf == nil {
		log.Info("COLIBRI not keeping any reservations")
		return nil, nil
	}
	log.Info("COLIBRI will keep reservations", "count", len(conf.Rsvs))
	initial := make([]requirements, len(conf.Rsvs))
	for i, r := range conf.Rsvs {
		seq, err := pathpol.NewSequence(r.PathPredicate)
		if err != nil {
			return nil, err
		}

		if r.RequiredCount <= 0 {
			return nil, serrors.New("required reservation count must be positive",
				"count", r.RequiredCount)
		}
		if r.MinSize > r.MaxSize {
			return nil, serrors.New("min bw must be less or equal than max bw",
				"min_bw", r.MinSize, "max_bw", r.MaxSize)
		}

		initial[i] = requirements{
			dst:           r.DstAS,
			pathType:      r.PathType,
			predicate:     seq,
			minBW:         r.MinSize,
			maxBW:         r.MaxSize,
			splitCls:      r.SplitCls,
			endProps:      reservation.PathEndProps(r.EndProps),
			minActiveRsvs: r.RequiredCount, // deleteme TODO remove required count
		}
	}
	return initial, nil
}

func parseInitialDeleteme(conf *conf.Reservations) (map[addr.IA][]requirementsDeleteme, error) {
	if conf == nil {
		log.Info("COLIBRI not keeping any reservations")
		return nil, nil
	}
	log.Info("COLIBRI will keep reservations", "count", len(conf.Rsvs))
	initial := make(map[addr.IA][]requirementsDeleteme)
	for _, r := range conf.Rsvs {
		seq, err := pathpol.NewSequence(r.PathPredicate)
		if err != nil {
			return nil, err
		}

		if r.RequiredCount <= 0 {
			return nil, serrors.New("required reservation count must be positive",
				"count", r.RequiredCount)
		}
		if r.MinSize > r.MaxSize {
			return nil, serrors.New("min bw must be less or equal than max bw",
				"min_bw", r.MinSize, "max_bw", r.MaxSize)
		}

		initial[r.DstAS] = append(initial[r.DstAS], requirementsDeleteme{
			pathType:      r.PathType,
			predicate:     seq,
			minBW:         r.MinSize,
			maxBW:         r.MaxSize,
			splitCls:      r.SplitCls,
			endProps:      reservation.PathEndProps(r.EndProps),
			minActiveRsvs: r.RequiredCount,
		})
	}
	return initial, nil
}

func printRsvs(rsvs []*seg.Reservation) string {
	strs := make([]string, len(rsvs))
	for i, r := range rsvs {
		strs[i] = "ID:" + r.ID.String()
	}
	return fmt.Sprintf("[%d] %s", len(rsvs), strings.Join(strs, ","))
}

func filterEmptyErrors(errs []error) []error {
	nonEmpty := make([]error, 0)
	for _, err := range errs {
		if err != nil {
			nonEmpty = append(nonEmpty, err)
		}
	}
	return nonEmpty
}
