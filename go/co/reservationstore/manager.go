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
	"strconv"
	"strings"
	"sync"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/conf"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/snet"
)

// Manager is what a colibri manager requires to expose.
type Manager interface {
	periodic.Task
	Now() time.Time
	LocalIA() addr.IA
	PathsTo(ctx context.Context, dst addr.IA) ([]snet.Path, error)
	GetReservationsAtSource(ctx context.Context) ([]*segment.Reservation, error)
	SetupRequest(ctx context.Context, req *segment.SetupReq) error
	ActivateRequest(context.Context, *base.Request, base.PathSteps, slayerspath.Path) error
	DeleteExpiredIndices(ctx context.Context) error
}

// manager takes care of the health of the segment reservations.
type manager struct {
	now                 func() time.Time // replace in tests
	wakeupTime          time.Time        // no need to do anything until this time
	wakeupListSegs      time.Time
	wakeupListE2Es      time.Time
	wakeupKeeper        time.Time // wake up the keeper (new rsvs/indices)
	wakeupExpirer       time.Time // wake up the colibri reservation expire routine
	wakeupAdmissionList time.Time
	keeper              *keeper // handles new rsvs/indices
	localIA             addr.IA
	store               reservationstorage.Store // TODO(juagargi) this should be an InitialStore
	router              snet.Router
}

func NewColibriManager(ctx context.Context, localIA addr.IA, router snet.Router,
	store reservationstorage.Store, initial *conf.Reservations) (Manager, error) {

	m := &manager{
		now:        time.Now,
		wakeupTime: time.Now().Add(-time.Nanosecond),
		localIA:    localIA,
		store:      store,
		router:     router,
	}

	keeper, err := NewKeeper(ctx, m, initial)
	if err != nil {
		return nil, err
	}
	m.keeper = keeper
	return m, nil
}

func (m *manager) Name() string {
	return "colibri.manager"
}

func (m *manager) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)

	now := time.Now()
	if now.Before(m.wakeupTime) {
		return
	}
	if !m.store.Ready() {
		log.Info("colibri store not yet ready")
		m.wakeupTime = m.Now().Add(2 * time.Second)
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(5)
	go func() { // periodic report of segment reservations
		defer log.HandlePanic()
		defer wg.Done()
		defer func() {
			m.wakeupListSegs = time.Now().Add(10 * time.Minute)
		}()
		// list segments
		rsvs, err := m.store.ReportSegmentReservationsInDB(ctx)
		if err != nil {
			log.Info("error reporting segment reservations in db", "err", err)
			return
		}
		table := make([]string, 0, len(rsvs)+1)
		table = append(table, fmt.Sprintf("%24s %4s %15s %4s %20s %11s %s",
			"id", "dir", "dst", "|i|", "exp", "rawpath_type", "path"))
		for _, r := range rsvs {
			table = append(table, fmt.Sprintf("%24s %4s %15s %4d %20s %11s %s",
				r.ID.String(),
				r.PathType,
				r.Steps.DstIA(),
				r.Indices.Len(),
				r.Indices.NewestExp().Format(time.Stamp),
				r.RawPath.Type(),
				r.Steps))
		}
		if len(rsvs) > 0 {
			log.Debug("----------- colibri segments ------------\n" + strings.Join(table, "\n") +
				"\n" + strings.Repeat("-", 150))
		}
	}()
	go func() { // periodic report of e2e reservations
		defer log.HandlePanic()
		defer wg.Done()
		defer func() {
			m.wakeupListE2Es = time.Now().Add(5 * time.Minute)
		}()
		// list e2e reservations
		rsvs, err := m.store.ReportE2EReservationsInDB(ctx)
		if err != nil {
			log.Info("error reporting e2e reservations in db", "err", err)
			return
		}
		table := make([]string, 0, len(rsvs)+1)
		table = append(table, fmt.Sprintf("%38s %8s %3s %3s %12s",
			"id", "alloc", "idx", "bw", "exptime"))
		for _, r := range rsvs {
			args := []interface{}{
				r.ID.String(),
				r.AllocResv(),
			}
			if len(r.Indices) > 0 {
				index := r.Indices[len(r.Indices)-1]
				args = append(args,
					strconv.Itoa(int(index.Idx)),
					strconv.Itoa(int(index.AllocBW)),
					index.Expiration.Format(time.StampMilli),
				)
			} else {
				args = append(args, "--", "---", "-------")
			}
			table = append(table, fmt.Sprintf("%38s %8d %3s %3s %12s", args...))
		}
		if len(rsvs) > 0 {
			log.Debug("___________ colibri e2e's now ___________\n" + strings.Join(table, "\n"))
		}
	}()
	go func() { // keep segment reservations (new setups and renewals)
		defer log.HandlePanic()
		defer wg.Done()
		if now.Before(m.wakeupKeeper) {
			return
		}
		logger.Debug("Reservation manager starting")
		defer logger.Debug("Reservation manager finished")

		// wakeupTime, err := m.keeper.OneShotDeleteme(ctx)
		wakeupTime, err := m.keeper.OneShot(ctx)
		if err != nil {
			logger.Info("error while keeping the reservations", "err", err)
		}
		logger.Info("will wait until the specified time", "wakeup_time", wakeupTime)
		m.wakeupKeeper = wakeupTime
	}()
	go func() { // periodic removal of expired indices (both segment & e2e)
		defer log.HandlePanic()
		defer wg.Done()
		if now.Before(m.wakeupExpirer) {
			return
		}
		n, wakeupTime, err := m.store.DeleteExpiredIndices(ctx, m.now())
		if err != nil {
			logger.Info("error deleting expired indices", "deleted_count", n, "err", err)
		}
		if n > 0 {
			logger.Debug("deleted expired indices", "count", n)
		}
		if wakeupTime.IsZero() {
			wakeupTime = now.Add(8 * time.Second)
		}
		m.wakeupExpirer = wakeupTime
	}()
	go func() { // periodic removal of expired admission entries (white/black lists)
		defer log.HandlePanic()
		defer wg.Done()
		if now.Before(m.wakeupAdmissionList) {
			return
		}
		n, wakeupTime, err := m.store.DeleteExpiredAdmissionEntries(ctx, m.now())
		if err != nil {
			logger.Info("error deleting expired admission list entries", "err", err)
		}
		if n > 0 {
			logger.Debug("deleted expired indices", "count", n)
		}
		if wakeupTime.IsZero() {
			wakeupTime = now.Add(8 * time.Second)
		}
		m.wakeupAdmissionList = wakeupTime
	}()
	wg.Wait()

	m.wakeupTime = findEarliest(
		m.wakeupListSegs,
		m.wakeupListE2Es,
		m.wakeupKeeper,
		m.wakeupExpirer,
		m.wakeupAdmissionList)
}

func (m *manager) DeleteExpiredIndices(ctx context.Context) error {
	_, _, err := m.store.DeleteExpiredIndices(ctx, m.now())
	return err
}

func (m *manager) Now() time.Time {
	return m.now()
}

func (m *manager) LocalIA() addr.IA {
	return m.localIA
}

func (m *manager) PathsTo(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	paths, err := m.router.AllRoutes(ctx, dst)
	log.Debug("colibri manager requested paths", "dst", dst, "count", len(paths), "err", err,
		"paths", paths)
	return paths, err
}

func (m *manager) GetReservationsAtSourceDeleteme(ctx context.Context, dst addr.IA) (
	[]*segment.Reservation, error) {

	return m.store.GetReservationsAtSourceDeleteme(ctx, dst)
}

func (m *manager) GetReservationsAtSource(ctx context.Context) (
	[]*segment.Reservation, error) {

	return m.store.GetReservationsAtSource(ctx)
}

func (m *manager) SetupRequest(ctx context.Context, req *segment.SetupReq) error {
	err := m.store.InitSegmentReservation(ctx, req)
	if err != nil {
		return err
	}
	// confirm new index
	confirmReq := base.NewRequest(m.now(), &req.Reservation.ID, req.Index, len(req.Steps))
	res, err := m.store.InitConfirmSegmentReservation(ctx, confirmReq, req.Steps, req.RawPath)
	if err != nil || !res.Success() {
		log.Info("failed to confirm the index", "id", req.ID, "idx", req.Index,
			"err", err, "res", res)
	}
	return err
}

func (m *manager) ActivateRequest(ctx context.Context, req *base.Request, steps base.PathSteps, path slayerspath.Path) error {
	res, err := m.store.InitActivateSegmentReservation(ctx, req, steps, path)
	if err != nil {
		return err
	}
	if !res.Success() {
		failure := res.(*base.ResponseFailure)
		return serrors.New("error activating index", "msg", failure.Message)
	}
	return nil
}

func findEarliest(times ...time.Time) time.Time {
	if len(times) == 0 {
		return time.Time{}
	}
	earliest := times[0]
	for i := 1; i < len(times); i++ {
		if times[i].Before(earliest) {
			earliest = times[i]
		}
	}
	return earliest
}
