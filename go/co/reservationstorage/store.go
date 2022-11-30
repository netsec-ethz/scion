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

package reservationstorage

import (
	"context"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	sgt "github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

// Store is the interface to interact with the reservation store.
type Store interface {
	Ready() bool
	// ListReservations is used to get segments to other ASes.
	ListReservations(ctx context.Context, dstIA addr.IA, pt reservation.PathType) (
		[]*colibri.SegRDetails, error)
	AdmitSegmentReservation(
		ctx context.Context,
		req *sgt.SetupReq,
	) (sgt.SegmentSetupResponse, error)
	ConfirmSegmentReservation(
		ctx context.Context,
		req *base.Request,
		transport *colpath.ColibriPathMinimal,
	) (base.Response, error)
	ActivateSegmentReservation(
		ctx context.Context,
		req *base.Request,
		transport *colpath.ColibriPathMinimal,
	) (base.Response, error)
	CleanupSegmentReservation(
		ctx context.Context,
		req *base.Request,
		transport *colpath.ColibriPathMinimal,
	) (base.Response, error)
	TearDownSegmentReservation(
		ctx context.Context,
		req *base.Request,
		transport *colpath.ColibriPathMinimal,
	) (base.Response, error)
	AdmitE2EReservation(
		ctx context.Context,
		req *e2e.SetupReq,
		transport *colpath.ColibriPathMinimal,
	) (e2e.SetupResponse, error)
	CleanupE2EReservation(
		ctx context.Context,
		req *e2e.Request,
		transport *colpath.ColibriPathMinimal,
	) (base.Response, error)

	// DeleteExpiredIndices returns the number of indices deleted, and the time for the
	// next expiration
	DeleteExpiredIndices(ctx context.Context, now time.Time) (int, time.Time, error)

	// -----------------------------------------------------------
	// as the source of reservations:

	// GetReservationsAtSource is used by a reservation manager or keeper to know all
	// reservations they must keep updated.
	GetReservationsAtSource(ctx context.Context) ([]*sgt.Reservation, error)
	// ListStitchableSegments is used by the endhosts. It will rely on calls to ListReservations
	// to this AS and other ASes.
	ListStitchableSegments(ctx context.Context, dst addr.IA) (*colibri.StitchableSegments, error)
	// InitSegmentReservation starts a new segment reservation.
	InitSegmentReservation(ctx context.Context, req *sgt.SetupReq) error
	// InitConfirmSegmentReservation initiates a confirm request.
	InitConfirmSegmentReservation(ctx context.Context, req *base.Request,
		steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
		base.Response, error)

	InitActivateSegmentReservation(ctx context.Context, req *base.Request,
		steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
		base.Response, error)

	InitCleanupSegmentReservation(ctx context.Context, req *base.Request,
		steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
		base.Response, error)

	InitTearDownSegmentReservation(ctx context.Context, req *base.Request,
		steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
		base.Response, error)

	// -----------------------------------------------------------
	// as the destination of reservations:

	// AddAdmissionEntry adds the auto-expiring entry to the admission list.
	// The store will check the validity date and trim it to the maximum allowed one.
	// The function returns the effective validity time for the entry.
	AddAdmissionEntry(ctx context.Context, entry *colibri.AdmissionEntry) (time.Time, error)

	// DeleteExpiredAdmissionEntries removes expired entries from the admission list.
	// It returns the number of entries removed, and the time when it should be called again.
	DeleteExpiredAdmissionEntries(ctx context.Context, now time.Time) (int, time.Time, error)

	ReportSegmentReservationsInDB(ctx context.Context) ([]*sgt.Reservation, error)
	ReportE2EReservationsInDB(ctx context.Context) ([]*e2e.Reservation, error)
}

// TODO(juagargi) create a Initiator store, a Transit store and a Destination store interfaces
