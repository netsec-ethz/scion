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

package client

import (
	"context"
	"crypto/rand"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// Reservation is an snet.Path like type that internally handles an e2e reservation.
// Two use it, one must first create one through a call to NewReservation, and then
// manage its lifetime with a call to Open and Close. Close must always be called
// to free up the resources after the Reservation is no longer needed.
// Internally, the Reservation has a periodic Runner handling the renewal of the reservation.
type Reservation struct {
	runner                 *periodic.Runner
	e2eRenewalTaskDuration time.Duration // tests modify this value

	daemon      daemon.Connector
	dstIA       addr.IA
	request     *colibri.E2EReservationSetup
	currentTrip *colibri.FullTrip // current trip for current setup
	colibriPath snet.Path
	onSuccess   RenewalSuccessHandler
	onError     RenewalErrorHandler
}

// LessFunction is used to sort full trips. The function should return true if
// a is preferred over b; false otherwise.
type LessFunction func(a, b colibri.FullTrip) bool

type RenewalSuccessHandler func(*Reservation)

// RenewalErrorHandler is a function that is called whenever there is an error during renewal.
// If it returns a FullTrip, the Reservation will try a new setup with it.
type RenewalErrorHandler func(*Reservation, error) *colibri.FullTrip

var _ snet.Path = (*Reservation)(nil)

// NewReservation
// The list of less functions is used to sort the full trips. The i+1 function
// is applied before the ith one, so the ith function takes preference over the i+1 (i.e. it's
// "more important" to the sorting).
func NewReservation(ctx context.Context,
	daemon daemon.Connector,
	localIA addr.IA, srcHost net.IP, dstIA addr.IA, dstHost net.IP,
	bw reservation.BWCls, index reservation.IndexNumber,
	lessFcns ...LessFunction) (*Reservation, error) {

	// 1. list segments from the scion daemon
	stitchable, err := daemon.ColibriListRsvs(ctx, dstIA)
	if err != nil {
		return nil, err
	}
	// 2. stitch segments according to lessFcn
	trips := colibri.CombineAll(stitchable)
	if len(trips) == 0 {
		return nil, serrors.New("no available stitched reservation to dst")
	}
	// sort using the functions in their reverse order (0th is most important, then 1st, etc)
	for i := len(lessFcns) - 1; i >= 0; i-- {
		lessFcn := lessFcns[i]
		sort.SliceStable(trips, func(a, b int) bool {
			return lessFcn(*trips[a], *trips[b])
		})
	}
	trip := trips[0]
	// 3. compute authenticators
	authenticators := [][]byte{} // deleteme TODO(juagargi)
	// 4. create setup reservation
	setupReq := &colibri.E2EReservationSetup{
		BaseRequest: colibri.BaseRequest{
			Id: reservation.ID{
				ASID:   localIA.AS(),
				Suffix: make([]byte, reservation.IDSuffixE2ELen),
			},
			Index:          index,
			SrcHost:        srcHost,
			DstHost:        dstHost,
			Path:           trip.Path(),
			Authenticators: authenticators,
		},
		RequestedBW: bw,
		Segments:    trip.Segments(),
	}
	rand.Read(setupReq.Id.Suffix) // random suffix
	return &Reservation{
		daemon:      daemon,
		dstIA:       dstIA,
		request:     setupReq,
		currentTrip: trip,
		// e2eRenewalTaskDuration is only a convenient way to modify the task duration at tests.
		// Since it's not exported, the compiler should see it's not reassigned via SSA, and just
		// treat it as a constant when not running a test.
		e2eRenewalTaskDuration: reservation.TicksInE2ERsv * reservation.DurationPerTick / 2,
	}, nil
}

// Open periodically sets up/renews the reservation. Returns error iff the setup failed.
// Everytime a new renewal succeeds, the success function is called. This is typically used
// by the callers to update e.g. destination addresses with the new colibriPath.
// On renewal error, it runs the callback and stops the periodic renewal if said
// function returns nil. If it returns a FullTrip, it is used to try to setup a new reservation.
func (r *Reservation) Open(ctx context.Context,
	successFcn RenewalSuccessHandler,
	fallbackFcn RenewalErrorHandler) error {

	if r.runner != nil {
		return nil
	}

	var err error
	r.colibriPath, err = r.daemon.ColibriSetupRsv(ctx, r.request)
	if err != nil {
		return serrors.WrapStr("first reservation setup failed", err)
	}
	if successFcn == nil {
		successFcn = func(*Reservation) {}
	}
	r.onSuccess = successFcn
	if fallbackFcn == nil {
		fallbackFcn = func(*Reservation, error) *colibri.FullTrip {
			return nil
		}
	}
	r.onError = fallbackFcn
	r.runner = periodic.Start(&renewalTask{
		reservation: r,
	}, r.e2eRenewalTaskDuration, r.e2eRenewalTaskDuration)
	return nil
}

func (r *Reservation) Close(ctx context.Context) error {
	if r.runner == nil {
		return nil
	}
	r.runner.Stop()
	r.runner = nil

	return r.daemon.ColibriCleanupRsv(ctx, &r.request.BaseRequest)
}

func (r *Reservation) CurrentTrip() colibri.FullTrip {
	return *r.currentTrip.Copy()
}

func (r *Reservation) UnderlayNextHop() *net.UDPAddr {
	return r.colibriPath.UnderlayNextHop()
}

func (r *Reservation) Dataplane() snet.DataplanePath {
	return r.colibriPath.Dataplane()
}

func (r *Reservation) Destination() addr.IA {
	return r.colibriPath.Destination()
}

func (r *Reservation) Metadata() *snet.PathMetadata {
	return r.colibriPath.Metadata()
}

// Copy is disallowed for a Reservation.
func (r *Reservation) Copy() snet.Path {
	panic("only one copy of a reservation must exist")
}

type renewalTask struct {
	reservation *Reservation
}

func (t *renewalTask) Name() string {
	return "colibri_renewal_task"
}

func (t *renewalTask) Run(ctx context.Context) {
	t.reservation.request.Index = t.reservation.request.Index.Add(1)
	for {
		colibriPath, err := t.reservation.daemon.ColibriSetupRsv(ctx, t.reservation.request)
		if err == nil {
			t.reservation.colibriPath = colibriPath
			t.reservation.onSuccess(t.reservation)
			return
		}
		trip := t.reservation.onError(t.reservation, err)
		if trip == nil {
			break // no fallback
		}
		t.reservation.request.Segments = trip.Segments()
	}
	// because it failed, stop the task (ourselves). Different routine for it (or deadlock)
	go func() {
		defer log.HandlePanic()
		t.reservation.runner.Stop() // blocks until the task exits. The task is this Run function
		t.reservation.runner = nil
	}()
}

func NewReservationForTesting(
	runner *periodic.Runner,
	e2eRenewalTaskDuration time.Duration,
	daemon daemon.Connector,
	dstIA addr.IA,
	request *colibri.E2EReservationSetup,
	currentTrip *colibri.FullTrip,
	connection *snet.Conn,
	colibriPath snet.Path,
	onError RenewalErrorHandler) *Reservation {

	return &Reservation{
		runner:                 runner,
		e2eRenewalTaskDuration: e2eRenewalTaskDuration,
		daemon:                 daemon,
		dstIA:                  dstIA,
		request:                request,
		currentTrip:            currentTrip,
		colibriPath:            colibriPath,
		onError:                onError,
	}
}
