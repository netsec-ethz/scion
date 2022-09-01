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
	"github.com/scionproto/scion/go/lib/snet"
)

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

// keeper looks after the reservations configured in reservations.json
// It starts by cleaning up those reservations that have expired.
// The keeper tries to match existing reservations with configured entries.
// If no match is found, a new reservation will be created.
type keeper struct {
	sleepUntil time.Time // nothing to do in the keeper until this time
	manager    Manager
	entries    []entry
}

type entry struct {
	conf *configuration
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
	entries := matchRsvsWithConfiguration(rsvs, reqs)

	log.Debug("colibri keeper", "reservations", len(entries))
	return &keeper{
		sleepUntil: time.Now().Add(-time.Nanosecond),
		manager:    manager,
		entries:    entries,
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
			err = k.activateIndex(ctx, e)
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
func matchRsvsWithConfiguration(rsvs []*seg.Reservation, conf []*configuration) []entry {
	conf = append(conf[:0:0], conf...)
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
		conf = append(conf[:i], conf[i+1:]...)
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
func findCompatibleConfiguration(r *seg.Reservation, conf []*configuration) int {
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
		return i
	}
	return -1
}

func (k *keeper) activateIndex(ctx context.Context, e *entry) error {
	req := base.NewRequest(k.manager.Now(), &e.rsv.ID, e.rsv.NextIndexToActivate().Idx,
		len(e.rsv.Steps))
	return k.manager.ActivateRequest(ctx, req, e.rsv.Steps.Copy(), e.rsv.RawPath)
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

// configuration is a 1 to 1 association to a conf.ReservationEntry
type configuration struct {
	dst       addr.IA
	pathType  reservation.PathType
	predicate *pathpol.Sequence
	minBW     reservation.BWCls
	maxBW     reservation.BWCls
	splitCls  reservation.SplitCls
	endProps  reservation.PathEndProps
}

type Compliance int

const (
	NeedsIndices    = Compliance(iota) // ask for a new index
	NeedsActivation                    // ask to activate index
	Compliant                          // already has an active compliant index
)

func (c Compliance) String() string {
	switch c {
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

// compliance finds the status of the reservation in regard with the configuration.
// It returns Compliant if it contains active indices compatible with the configuration,
// NeedsActivation if the compatible index(es) exist but need to be activated, or
// NeedsIndices if no compatible index exists.
// The function expects a non-nil reservation.
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

func parseInitial(conf *conf.Reservations) ([]*configuration, error) {
	if conf == nil {
		log.Info("COLIBRI not keeping any reservations")
		return nil, nil
	}
	log.Info("COLIBRI will keep reservations", "count", len(conf.Rsvs))
	initial := make([]*configuration, len(conf.Rsvs))
	for i, r := range conf.Rsvs {
		seq, err := pathpol.NewSequence(r.PathPredicate)
		if err != nil {
			return nil, err
		}

		if r.MinSize > r.MaxSize {
			return nil, serrors.New("min bw must be less or equal than max bw",
				"min_bw", r.MinSize, "max_bw", r.MaxSize)
		}

		initial[i] = &configuration{
			dst:       r.DstAS,
			pathType:  r.PathType,
			predicate: seq,
			minBW:     r.MinSize,
			maxBW:     r.MaxSize,
			splitCls:  r.SplitCls,
			endProps:  reservation.PathEndProps(r.EndProps),
		}
	}
	return initial, nil
}
