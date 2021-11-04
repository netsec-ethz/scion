// Copyright 2021 ETH Zurich, Anapaya Systems
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
	"math"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/segment/admission"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/coliquic"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

const MaxAdmissionEntryValidity = time.Minute

// Store is the reservation store.
type Store struct {
	localIA       addr.IA
	isCore        bool
	db            backend.DB                      // aka reservation map
	admitter      admission.Admitter              // the chosen admission entity
	operator      *coliquic.ServiceClientOperator // dials next colibri service
	authenticator Authenticator                   // source authentication based on drkey
	colibriKey    []byte                          // colibri secret key
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(topo *topology.Loader, sd daemon.Connector, router snet.Router,
	dialer coliquic.GRPCClientDialer, db backend.DB, admitter admission.Admitter,
	masterKey []byte) (*Store, error) {

	// check that the admitter is well configured
	cap := admitter.Capacities()
	for _, ifid := range append(topo.InterfaceIDs(), 0) {
		log.Info("colibri admission capacity", "ifid", ifid,
			"ingress", cap.CapacityIngress(uint16(ifid)),
			"egress", cap.CapacityEgress(uint16(ifid)))
	}
	operator, err := coliquic.NewServiceClientOperator(topo, router, dialer)
	if err != nil {
		return nil, err
	}
	colibriKey := scrypto.DeriveColibriMacKey(masterKey)
	return &Store{
		localIA:       topo.IA(),
		isCore:        topo.Core(),
		db:            db,
		admitter:      admitter,
		operator:      operator,
		authenticator: NewDrkeyAuthenticator(topo.IA(), sd),
		colibriKey:    colibriKey,
	}, nil
}

func (s *Store) err(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("@%s: %s", s.localIA, err)
}

func (s *Store) errNew(msg string, params ...interface{}) error {
	return s.err(serrors.New(msg, params...))
}

func (s *Store) errWrapStr(msg string, err error, params ...interface{}) error {
	return s.err(serrors.WrapStr(msg, err, params...))
}

func (s *Store) ReportSegmentReservationsInDB(ctx context.Context) (
	[]*segment.Reservation, error) {

	return s.db.GetAllSegmentRsvs(ctx)
}

func (s *Store) ReportE2EReservationsInDB(ctx context.Context) ([]*e2e.Reservation, error) {
	return s.db.GetAllE2ERsvs(ctx)
}

func (s *Store) GetReservationsAtSource(ctx context.Context, dstIA addr.IA) (
	[]*segment.Reservation, error) {

	return s.db.GetSegmentRsvsFromSrcDstIA(ctx, s.localIA, dstIA, reservation.UnknownPath)
}

// ListStitchableSegments will first get the rsv. segments starting from this store.
// It may dial two times more to two external AS colibri services, to get core and down
// segments.
func (s *Store) ListStitchableSegments(ctx context.Context, dst addr.IA) (
	*colibri.StitchableSegments, error) {

	log.Debug("listing stitchable segments", "dst", dst)
	// The function obtains first all the up segments to core (if the local AS is non-core).
	// If core, it adds itself to the local ISD reachable core ASes.
	// The function then finds all core segments from the reachable local ISD core ASes to
	// the core ISD of the destination.
	// The function then finds all the down segments from the reachable remote core ISD to the
	// destination.
	// Additionally, if the local ISD is the same as the remote ISD, the function tries to find
	// up segments to the destination.
	response := &colibri.StitchableSegments{
		SrcIA: s.localIA,
		DstIA: dst,
		Up:    make([]*colibri.ReservationLooks, 0),
		Core:  make([]*colibri.ReservationLooks, 0),
		Down:  make([]*colibri.ReservationLooks, 0),
	}
	var err error

	localIsdCores := make(map[addr.IA]struct{}) // set of reachable local ISD core ASes
	localCore, _ := addr.IAFrom(s.localIA.ISD(), 0)
	if !s.isCore {
		response.Up, err = s.obtainRsvs(ctx, s.localIA, localCore, reservation.UpPath)
		if err != nil {
			return nil, serrors.WrapStr("listing stitchable segments, up", err,
				"src", "local", "dst", localCore.String())
		}
		for _, r := range response.Up {
			localIsdCores[r.DstIA] = struct{}{}
		}
	} else {
		localIsdCores[s.localIA] = struct{}{}
	}

	// from core of local ISD to core of destination ISD:
	// TODO(juagargi) run all this in parallel with go routines.
	remoteIsdCore, _ := addr.IAFrom(dst.ISD(), 0)
	for core := range localIsdCores {
		cores, err := s.obtainRsvs(ctx, core, remoteIsdCore, reservation.CorePath)
		if err != nil {
			return nil, serrors.WrapStr("listing stitchable segments, core", err,
				"src", core.String(), "dst", remoteIsdCore.String())
		}
		response.Core = append(response.Core, cores...)
	}
	farIsdCores := make(map[addr.IA]struct{}) // set of reachable remote ISD core ASes
	for _, r := range response.Core {
		farIsdCores[r.DstIA] = struct{}{}
	}
	if s.localIA.ISD() == dst.ISD() {
		// if the ISD is the same, farIsdCores is a superset of localIsdCores
		for localCore := range localIsdCores {
			farIsdCores[localCore] = struct{}{}
		}
	}
	// from core of destination ISD to final destination:
	for remoteCore := range farIsdCores {
		down, err := s.obtainRsvs(ctx, remoteCore, dst, reservation.DownPath)
		if err != nil {
			return nil, serrors.WrapStr("listing stitchable segments, down", err,
				"src", remoteCore.String(), "dst", dst.String())
		}
		response.Down = append(response.Down, down...)
	}

	// additionally, if the ISD is the same, and we didn't find an up segment when trying to
	// reach the local ISD core, it means that the destination is non core, and that maybe we can
	// reach it directly with an up segment: look for an up segment to the destination
	if _, ok := localIsdCores[dst]; !ok && s.localIA.ISD() == dst.ISD() {
		up, err := s.obtainRsvs(ctx, s.localIA, dst, reservation.UpPath)
		if err != nil {
			return nil, serrors.WrapStr("listing stitchable segments, up direct", err,
				"src", "local", "dst", localCore.String())
		}
		// note: we couldn't possibly find these up segments before: the dst is non-core.
		response.Up = append(response.Up, up...)
	}

	// TODO(juagargi) we could use a local DB to cache the results, like the path query does.
	return response, nil
}

// InitSegmentReservation will start a new segment reservation request. The source of
// the request will have this very AS as source.
func (s *Store) InitSegmentReservation(ctx context.Context, req *segment.SetupReq) error {
	if req.IsLastAS() {
		return s.errNew("cannot initiate a reservation with this AS only in the path")
	}
	if req.ID.IsEmpty() {
		return serrors.New("bad empty ID")
	}
	if req.ID.ASID != s.localIA.AS() {
		return s.errNew("bad reservation id", "as", req.ID.ASID)
	}

	newSetup := false
	if req.ID.IsEmptySuffix() {
		newSetup = true
	}

	rsv, err := s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return s.errWrapStr("cannot obtain segment reservation", err, "id", req.ID.String())
	}
	if rsv != nil && newSetup {
		return s.errNew("found existing reservation in db for a new setup", "id", req.ID.String())
	} else if rsv == nil && !newSetup {
		return s.errNew("reservation not found for a renewal", "id", req.ID.String())
	}
	log.Info("COLIBRI requesting setup/renewal", "new_setup", newSetup,
		"id", req.ID.String(), "idx", req.Index, "dst_ia", req.Path.DstIA(), "path", req.Path)

	origPath := req.Request.Path.Copy()
	rollbackChanges := func(setupRes segment.SegmentSetupResponse) {
		if failure, ok := setupRes.(*segment.SegmentSetupResponseFailure); ok {
			if !req.ReverseTraveling {
				if len(failure.FailedRequest.AllocTrail)+1 < len(origPath.Steps) {
					// shorten the path to exclude those nodes the request never transited.
					// the last node in allocTrail could (or not) have stored the index and
					// thus would need cleaning.
					origPath.Steps = origPath.Steps[:len(failure.FailedRequest.AllocTrail)+1]
				}
			}
		}
		if len(origPath.Steps) < 2 {
			// only this AS to contact (or not even here), just don't send any RPC
			return
		}
		// uses the `req` that will have the new ID and index, but the original path
		req := base.NewRequest(req.Timestamp, &req.ID, req.Index, origPath)
		var res base.Response
		var err error
		if newSetup {
			res, err = s.InitTearDownSegmentReservation(ctx, req)
		} else {
			res, err = s.InitCleanupSegmentReservation(ctx, req)
		}
		if err != nil {
			log.Info("while cleaning reservations down the path an error occurred",
				"new_setup", newSetup, "err", err, "res", res)
		} else if _, ok := res.(*base.ResponseSuccess); !ok {
			log.Info("while cleaning reservations down the path, received failure response",
				"new_setup", newSetup, "res", res)
		}
		log.Debug("reservation has been rollback", "new_setup", newSetup)
	}
	// create new reservation in DB
	if rsv == nil { // new setup
		rsv = segment.NewReservation(req.ID.ASID)
		rsv.ID = req.ID
		rsv.Ingress = req.Ingress()
		rsv.Egress = req.Egress()
		rsv.PathType = req.PathType
		rsv.PathEndProps = req.PathProps
		rsv.TrafficSplit = req.SplitCls
		rsv.PathAtSource = req.Path

		if err := s.db.NewSegmentRsv(ctx, rsv); err != nil {
			return s.errWrapStr("initial reservation creation", err, "dst", req.Path.DstIA())
		}
		req.ID = rsv.ID // the DB created a new suffix for the rsv.; copy it to the request
	}

	var res segment.SegmentSetupResponse
	if req.PathType == reservation.DownPath {
		// reverse_traveling must be true if this is a down rsv. and this AS is non core.
		// It must be false otherwise.
		// The flag indicates the admission to send the request to
		// the last AS of the path to re-start the request process from there, as the
		// admission must be computed in the direction of the reservation.
		req.ReverseTraveling = !s.isCore
		res, err = s.sendUpstreamForAdmission(ctx, req)
	} else {
		err = s.authenticator.ComputeSegmentSetupRequestInitialMAC(ctx, req)
		if err != nil {
			return err
		}
		res, err = s.admitSegmentReservation(ctx, req)
	}
	if err != nil {
		rollbackChanges(res)
		return err
	}
	// TODO(juagargi) deprecate the use of ReverseTraveling and all the complexity that it involves.
	if req.PathType != reservation.DownPath {
		ok, err := s.authenticator.ValidateSegmentSetupResponse(ctx, res, req.Path)
		if !ok || err != nil {
			return s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	}
	if _, ok := res.(*segment.SegmentSetupResponseSuccess); !ok {
		rollbackChanges(res)
		return serrors.New("failure in setup", "response", res)
	}

	return nil
}

func (s *Store) InitConfirmSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("initializing confirm segment reservation", err)
	}
	return s.ConfirmSegmentReservation(ctx, req)

}

func (s *Store) InitActivateSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("initializing activate segment reservation", err)
	}
	return s.ActivateSegmentReservation(ctx, req)
}

func (s *Store) InitCleanupSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("initializing clean segment reservation", err)
	}
	return s.CleanupSegmentReservation(ctx, req)
}

func (s *Store) InitTearDownSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("initializing teardown segment reservation", err)
	}
	return s.TearDownSegmentReservation(ctx, req)
}

func (s *Store) ListReservations(ctx context.Context, dstIA addr.IA,
	pathType reservation.PathType) ([]*colibri.ReservationLooks, error) {
	rsvs, err := s.db.GetSegmentRsvsFromSrcDstIA(ctx, s.localIA, dstIA, pathType)
	if err != nil {
		log.Error("listing reservations", "err", err)
		return nil, s.err(err)
	}
	return reservationsToLooks(rsvs, s.localIA), nil
}

// AddAdmissionEntry adds an entry to the admission list. It returns the deadline for the entry.
func (s *Store) AddAdmissionEntry(ctx context.Context, entry *colibri.AdmissionEntry) (
	time.Time, error) {

	maxDeadline := time.Now().Add(MaxAdmissionEntryValidity)
	if entry.ValidUntil.After(maxDeadline) {
		entry.ValidUntil = maxDeadline
	}
	err := s.db.AddToAdmissionList(ctx, entry.ValidUntil, entry.DstHost,
		entry.RegexpIA, entry.RegexpHost, entry.AcceptAdmission)
	log.Debug("added entry to admission list", "host", entry.DstHost.String(),
		"valid_until", util.TimeToCompact(entry.ValidUntil), "admit", entry.AcceptAdmission,
		"regexp_ia", entry.RegexpIA, "regexp_host", entry.RegexpHost)
	return entry.ValidUntil, err
}

func (s *Store) DeleteExpiredAdmissionEntries(ctx context.Context, now time.Time) (
	int, time.Time, error) {

	n, err := s.db.DeleteExpiredAdmissionEntries(ctx, now)
	if err != nil {
		return 0, time.Time{}, err
	}
	return n, now.Add(MaxAdmissionEntryValidity), nil
}

// AdmitSegmentReservation receives a setup/renewal request to admit a segment reservation.
// It is expected that this AS is not the reservation initiator.
func (s *Store) AdmitSegmentReservation(ctx context.Context, req *segment.SetupReq) (
	segment.SegmentSetupResponse, error) {

	if req.ReverseTraveling {
		return s.sendUpstreamForAdmission(ctx, req)
	}

	if err := s.authenticateSegSetupReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	return s.admitSegmentReservation(ctx, req)
}

// ConfirmSegmentReservation changes the state of an index from temporary to confirmed.
func (s *Store) ConfirmSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	if err := s.authenticateReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "failed to confirm index",
	}
	if !req.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse, req.Path); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		failedResponse.Message = "no reservation found"
		return failedResponse, nil
	}
	if err := rsv.SetIndexConfirmed(req.Index); err != nil {
		return failedResponse, s.errWrapStr("cannot set index to confirmed", err,
			"id", req.ID.String())
	}

	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, s.errWrapStr("cannot persist segment reservation", err,
			"id", req.ID.String())
	}

	var res base.Response
	if req.IsLastAS() {
		res = &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Path.Steps)-1),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	} else {
		// authenticate request for the destination AS
		if err := s.authenticator.ComputeRequestTransitMAC(ctx, req); err != nil {
			return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
		}

		// forward to next colibri service
		client, err := s.operator.ColibriClient(ctx, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("while finding a colibri service client", err)
		}

		base, err := translate.PBufRequest(req)
		if err != nil {
			return failedResponse, s.err(err)
		}
		pbRes, err := client.ConfirmSegmentIndex(ctx,
			&colpb.ConfirmSegmentIndexRequest{Base: base})
		if err != nil {
			return failedResponse, s.errWrapStr("forwarded request failed", err)
		}
		res = translate.Response(pbRes.Base)
		if req.IsFirstAS() {
			ok, err := s.authenticator.ValidateResponse(ctx, res, req.Path)
			if !ok || err != nil {
				return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
					"id", req.ID)
			}
		} else {
			// create authenticators before passing the response to the previous node in the path
			if err := s.authenticator.ComputeResponseMAC(ctx, res, req.Path); err != nil {
				return failedResponse, s.errWrapStr("computing authenticators for response", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}
	return res, err
}

// ActivateSegmentReservation activates a segment reservation index.
func (s *Store) ActivateSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	// TODO(juagargi) refactor these functions that share a lot of code
	if err := s.authenticateReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "failed to activate index",
	}
	if !req.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse, req.Path); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		failedResponse.Message = "no reservation found"
		return failedResponse, nil
	}
	if err := rsv.SetIndexActive(req.Index); err != nil {
		return failedResponse, s.errWrapStr("cannot set index to active", err,
			"id", req.ID.String())
	}

	if isFirstASInReservation(rsv, req) {
		transpPath, err := newTransparentPathFromReservation(rsv)
		if err != nil {
			log.Error("error obtaining colibri path from reservation", "err", err)
		} else {
			// if no errors, use the colibri path
			rsv.PathAtSource = transpPath
		}
	}
	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, s.errWrapStr("cannot persist segment reservation", err,
			"id", req.ID.String())
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}

	if req.IsLastAS() {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Path.Steps)-1),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		return failedResponse, s.errWrapStr("while finding a colibri service client", err)
	}

	base, err := translate.PBufRequest(req)
	if err != nil {
		return failedResponse, s.errWrapStr("translation failed", err)
	}
	pbRes, err := client.ActivateSegmentIndex(ctx,
		&colpb.ActivateSegmentIndexRequest{Base: base})
	if err != nil {
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if req.IsFirstAS() {
		ok, err := s.authenticator.ValidateResponse(ctx, res, req.Path)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, req.Path); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// CleanupSegmentReservation deletes an index from a segment reservation.
func (s *Store) CleanupSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	if err := s.authenticateReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "failed to cleanup index",
	}
	if !req.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse, req.Path); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		failedResponse.Message = "no reservation found"
		return failedResponse, nil
	}

	if err := rsv.RemoveIndex(req.Index); err != nil {
		// log error but continue
		log.Info("error cleaning segment index, continuing anyway", "err", err)
	}

	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, s.errWrapStr("cannot persist segment reservation", err,
			"id", req.ID.String())
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}

	if req.IsLastAS() {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Path.Steps)-1),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		return failedResponse, s.errWrapStr("while finding a colibri service client", err)
	}

	base, err := translate.PBufRequest(req)
	if err != nil {
		return failedResponse, s.errWrapStr("translation failed", err)
	}
	pbRes, err := client.CleanupSegmentIndex(ctx,
		&colpb.CleanupSegmentIndexRequest{Base: base})
	if err != nil {
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if req.IsFirstAS() {
		ok, err := s.authenticator.ValidateResponse(ctx, res, req.Path)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, req.Path); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// TearDownSegmentReservation removes a whole segment reservation.
func (s *Store) TearDownSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {

	if err := s.authenticateReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "failed to teardown index",
	}
	if !req.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse, req.Path); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()

	if err := tx.DeleteSegmentRsv(ctx, &req.ID); err != nil {
		return failedResponse, s.errWrapStr("cannot teardown reservation", err,
			"id", req.ID.String())
	}

	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}

	if req.IsLastAS() {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Path.Steps)-1),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		return failedResponse, s.errWrapStr("while finding a colibri service client", err)
	}

	base, err := translate.PBufRequest(req)
	if err != nil {
		return failedResponse, s.errWrapStr("translation failed", err)
	}
	pbRes, err := client.TeardownSegment(ctx,
		&colpb.TeardownSegmentRequest{Base: base})
	if err != nil {
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if req.IsFirstAS() {
		ok, err := s.authenticator.ValidateResponse(ctx, res, req.Path)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, req.Path); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// AdmitE2EReservation will attempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(ctx context.Context, req *e2e.SetupReq) (
	e2e.SetupResponse, error) {

	log.Debug("e2e admission request", "id", req.ID, "path", req.Path,
		"segments", reservation.IDs(req.SegmentRsvs), "curr_segment", req.CurrentSegmentRsvIndex)

	if err := s.authenticateE2eSetupReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &e2e.SetupResponseFailure{
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "cannot admit e2e reservation",
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = s.errWrapStr("request failed validation", err).Error()
		log.Debug("e2e request validation failed", "err", err)
		return failedResponse, nil
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		err := s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
		failedResponse.Message = err.Error()
		return failedResponse, err
	}
	defer tx.Rollback()

	rsv, err := tx.GetE2ERsvFromID(ctx, &req.ID)
	if err != nil {
		err := s.errWrapStr("cannot obtain e2e reservation", err, "id", req.ID.String())
		failedResponse.Message = err.Error()
		log.Error("retrieving e2e reservation", "err", err)
		return failedResponse, err
	}
	newSetup := (rsv == nil)

	if newSetup {
		rsv = &e2e.Reservation{

			ID:                  req.ID,
			Path:                req.Path.Copy(),
			SegmentReservations: make([]*segment.Reservation, 0),
		}
		for _, id := range req.SegmentRsvs {
			r, err := tx.GetSegmentRsvFromID(ctx, &id)
			if err != nil {
				return failedResponse, s.errWrapStr("loading segment rsv for e2e admission",
					err, "e2e_id", req.ID, "seg_id", id)
			}
			if r != nil {
				rsv.SegmentReservations = append(rsv.SegmentReservations, r)
			}
		}
	} else {
		if index := rsv.Index(req.Index); index != nil {
			// renewal with index clash
			failedResponse.Message = s.errNew("already existing e2e index", "id", req.ID.String(),
				"idx", req.Index).Error()
			return failedResponse, nil
		}
		assert(len(rsv.SegmentReservations) < 3, "logic error, too many segments in AS. ID: %s, "+
			"seg. ids: %s", req.ID, req.SegmentRsvs)
		// TODO(juagargi) check rsv.Path and req.Path coincide
	}
	isTransfer := false
	if len(rsv.SegmentReservations) > 1 {
		isTransfer = true
		assert(len(rsv.SegmentReservations) == 2, "logic error: too many segments in AS: %v",
			rsv.SegmentReservations)
		assert(rsv.SegmentReservations[0].PathAtSource.DstIA().Equal(s.localIA),
			"logic error: incoming segment in transfer node doesn't end here. Segs: %s, "+
				"first segment: %s, second segment: %s", req.SegmentRsvs,
			rsv.SegmentReservations[0].PathAtSource, rsv.SegmentReservations[1].PathAtSource)
	}
	log.Info("deleteme e2e admission processing", "is_transfer", isTransfer, "segs", rsv.SegmentReservations)

	// check the seg. reservations
	expTime := util.MaxFutureTime()
	for _, r := range rsv.SegmentReservations {
		if r.ActiveIndex() == nil {
			failedResponse.Message = s.errNew("seg. rsv. for e2e rsv has no active index",
				"id", req.ID, "seg_id", r.ID, "indices", r.Indices.String()).Error()
			return failedResponse, nil
		}
		if expTime.After(r.ActiveIndex().Expiration) {
			expTime = r.ActiveIndex().Expiration
		}
	}

	maxExpTime := time.Now().Add(reservation.E2ERsvDuration)
	if maxExpTime.Before(expTime) {
		expTime = maxExpTime
	}
	idx, err := rsv.NewIndex(expTime, req.RequestedBW)
	if err != nil {
		failedResponse.Message = s.errWrapStr("cannot create index in e2e admission", err,
			"e2e_id", req.ID).Error()
		return failedResponse, nil
	}
	index := rsv.Index(idx)

	// admission
	free, err := freeInSegRsv(ctx, tx, rsv.SegmentReservations[0])
	if err != nil {
		failedResponse.Message = s.errWrapStr("cannot compute free bw for e2e admission", err,
			"e2e_id", rsv.ID).Error()
		return failedResponse, nil
	}
	if !newSetup {
		free = free + rsv.AllocResv() // don't count this E2E request in the used BW
	}

	if isTransfer {
		freeOutgoing, err := freeAfterTransfer(ctx, tx, rsv, !newSetup)
		if err != nil {
			failedResponse.Message = s.errWrapStr("cannot compute transfer", err,
				"id", req.ID).Error()
			return failedResponse, nil
		}
		log.Info("deleteme", "free", free, "free_outgoing", freeOutgoing)
		if free > freeOutgoing {
			free = freeOutgoing
		}
	}
	// always store the computed free BW in the request
	req.AllocationTrail = append(req.AllocationTrail, reservation.BWClsFromBW(free))
	admitted := true
	failedStep := -1
	for i, step := range req.AllocationTrail {
		if step < req.RequestedBW {
			admitted = false
			failedStep = i
			break
		}
	}

	log.Debug("e2e admission", "id", req.ID.String(), "requested_cls", req.RequestedBW,
		"requested", req.RequestedBW.ToKbps(), "admitted", admitted, "free", free)

	var token *reservation.Token
	if req.IsLastAS() {
		var notAdmittedMsg string
		if admitted {
			// check white/black (admission) list of endhost
			admitted = false
			res, err := tx.CheckAdmissionList(ctx, time.Now(), req.DstHost,
				req.Path.SrcIA(), req.SrcHost.String())
			log.Debug("checked admission list", "admit", res, "err", err,
				"host", req.DstHost.String(), "src_ia", req.Path.SrcIA(), "src_host", req.SrcHost)
			switch {
			case err != nil:
				notAdmittedMsg = fmt.Sprintf("error in admission list: %s", err)
			case res < 0:
				notAdmittedMsg = "endhost denied the admission"
			case res == 0:
				notAdmittedMsg = "endhost did not explicitly admit (too busy)"
			case res > 0:
				admitted = true
			}
		}
		if !admitted {
			if notAdmittedMsg == "" {
				notAdmittedMsg = "not admitted"
			}
			return &e2e.SetupResponseFailure{
				Message:    notAdmittedMsg,
				FailedStep: uint8(failedStep),
				AllocTrail: req.AllocationTrail,
			}, nil
		}
		token = index.Token
	} else { // this is not the last AS
		if isTransfer {
			// indicate the next node we are using the next segment:
			req.CurrentSegmentRsvIndex++
		}
		if err := s.authenticator.ComputeE2eSetupRequestTransitMAC(ctx, req); err != nil {
			return nil, serrors.WrapStr("computing in transit e2e setup request authenticator", err)
		}
		// authenticate request for the destination AS
		client, err := s.operator.ColibriClient(ctx, req.Path)
		if err != nil {
			return nil, serrors.WrapStr("while finding a colibri service client", err)
		}

		pbReq, err := translate.PBufE2ESetupReq(req)
		if err != nil {
			failedResponse.Message = s.errWrapStr("translation failed", err).Error()
			return failedResponse, nil
		}
		// forward to next colibri service
		pbRes, err := client.E2ESetup(ctx, pbReq)
		if err != nil {
			failedResponse.Message = s.errWrapStr("cannot forward request", err).Error()
			return failedResponse, nil
		}
		res, err := translate.E2ESetupResponse(pbRes)
		if err != nil {
			return nil, serrors.WrapStr("translating response", err)
		}
		success, ok := res.(*e2e.SetupResponseSuccess)
		if !ok {
			// not admitted
			return res, nil
		}
		token, err = reservation.TokenFromRaw(success.Token)
		if err != nil {
			failedResponse.Message = s.errWrapStr("decoding token from node ahead", err).Error()
			return failedResponse, nil
		}
	}
	// here the request was admitted and returning back from the down stream admission

	step := req.Path.Steps[req.Path.CurrentStep]
	err = s.computeMAC(rsv.ID.Suffix, token, req.ID.ASID, req.ID.ASID, step.Ingress, step.Egress)
	if err != nil {
		failedResponse.Message = s.errWrapStr("cannot compute MAC", err).Error()
		return failedResponse, err
	}
	index.Token = token

	if err := tx.PersistE2ERsv(ctx, rsv); err != nil {
		return failedResponse, s.errWrapStr("cannot persist e2e reservation", err,
			"id", req.ID.String())
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}
	// return the token upstream
	return &e2e.SetupResponseSuccess{
		Token: token.ToRaw(),
	}, nil
}

// CleanupE2EReservation will remove an index from an e2e reservation.
func (s *Store) CleanupE2EReservation(ctx context.Context, req *e2e.Request) (
	base.Response, error) {

	if err := s.authenticateE2eReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	log.Debug("e2e cleanup request", "id", req.ID, "path", req.Path)
	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep: uint8(req.Path.CurrentStep),
		Message:    "failed to cleanup e2e index",
	}
	if !req.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse, req.Path); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}

	rsv, err := s.db.GetE2ERsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, s.errWrapStr("obtaining e2e reservation", err,
			"id", req.ID.String())
	}

	if rsv.Index(req.Index) != nil {
		tx, err := s.db.BeginTransaction(ctx, nil)
		if err != nil {
			return failedResponse, s.errWrapStr("cannot create transaction", err,
				"id", req.ID.String())
		}
		defer tx.Rollback()
		if err := rsv.RemoveIndex(req.Index); err != nil {
			return failedResponse, s.errWrapStr("cannot delete e2e reservation index", err,
				"id", req.ID.String(), "index", req.Index)
		}
		if len(rsv.Indices) == 0 {
			if err := tx.DeleteE2ERsv(ctx, &rsv.ID); err != nil {
				return failedResponse, s.errWrapStr("cannot delete e2e reservation", err,
					"id", rsv.ID)
			}
		} else if err := tx.PersistE2ERsv(ctx, rsv); err != nil {
			return failedResponse, s.errWrapStr("cannot persist e2e reservation", err,
				"id", req.ID.String())
		}
		if err := tx.Commit(); err != nil {
			return failedResponse, s.errWrapStr("cannot commit transaction", err,
				"id", req.ID.String())
		}
	}

	if req.IsLastAS() {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Path.Steps)-1),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, req.Path)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}
	// authenticate the semi mutable parts of the request, to be validated at the destination
	if err := s.authenticator.ComputeE2eRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit e2e base request authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		return failedResponse, s.errWrapStr("while finding a colibri service client", err)
	}

	base, err := translate.PBufE2ERequest(req)
	if err != nil {
		return failedResponse, s.errWrapStr("translation failed", err)
	}
	pbRes, err := client.CleanupE2EIndex(ctx,
		&colpb.CleanupE2EIndexRequest{Base: base})
	if err != nil {
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if req.IsFirstAS() {
		ok, err := s.authenticator.ValidateResponse(ctx, res, req.Path)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, req.Path); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// DeleteExpiredIndices will just call the DB's method to delete the expired indices.
func (s *Store) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, time.Time, error) {
	n, err := s.db.DeleteExpiredIndices(ctx, now)
	if err != nil {
		return 0, time.Time{}, serrors.WrapStr("deleting expired indices", err)
	}
	exp, err := s.db.NextExpirationTime(ctx)
	// we will return the next expiration time as earliest(now+16 , exp)
	if exp.After(time.Now().Add(reservation.E2ERsvDuration)) {
		exp = time.Now().Add(reservation.E2ERsvDuration)
	}
	return n, exp, err
}

// authenticateReq checks that the authenticators are correct.
func (s *Store) authenticateReq(ctx context.Context, req *base.Request) error {
	if req.IsFirstAS() {
		return nil
	}
	ok, err := s.authenticator.ValidateRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// authenticateSegSetupReq checks that the authenticators are correct.
func (s *Store) authenticateSegSetupReq(ctx context.Context, req *segment.SetupReq) error {
	ok, err := s.authenticator.ValidateSegSetupRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// authenticateE2eReq checks that the authenticators are correct.
func (s *Store) authenticateE2eReq(ctx context.Context, req *e2e.Request) error {
	ok, err := s.authenticator.ValidateE2eRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// authenticateE2eSetupReq checks that the authenticators are correct.
func (s *Store) authenticateE2eSetupReq(ctx context.Context, req *e2e.SetupReq) error {
	ok, err := s.authenticator.ValidateE2eSetupRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

func (s *Store) admitSegmentReservation(ctx context.Context, req *segment.SetupReq) (
	segment.SegmentSetupResponse, error) {

	failedResponse := &segment.SegmentSetupResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
		FailedStep:    uint8(req.Path.CurrentStep),
		FailedRequest: req,
	}
	updateResponse := func(res segment.SegmentSetupResponse) (segment.SegmentSetupResponse, error) {
		if !req.IsFirstAS() {
			if err := s.authenticator.ComputeSegmentSetupResponseMAC(ctx, failedResponse,
				req.Path); err != nil {

				return nil, serrors.WrapStr("computing seg. setup response authentication", err)
			}
		}
		return res, nil
	}

	log.Debug("segment admission", "id", req.ID, "src_ia", req.Path.SrcIA(),
		"dst_ia", req.Path.DstIA(), "path", req.Path)
	if err := req.Validate(); err != nil {
		failedResponse.Message = s.errWrapStr("request failed validation", err).Error()
		return updateResponse(failedResponse)
	}

	if req.ID.IsEmptySuffix() {
		failedResponse.Message = s.errNew("empty suffix not allowed").Error()
		return updateResponse(failedResponse)
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, s.errWrapStr("cannot create transaction", err,
			"id", req.ID.String())
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		failedResponse.Message = "looking for reservation: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}

	if rsv != nil { // renewal, ensure index is not used
		if rsv.Index(req.Index) != nil {
			failedResponse.Message = fmt.Sprintf("index from setup already in use: %d", req.Index)
			return updateResponse(failedResponse)
		}
	} else {
		rsv = segment.NewReservation(req.ID.ASID)
		rsv.ID = req.ID
		rsv.Ingress = req.Ingress()
		rsv.Egress = req.Egress()
		rsv.PathType = req.PathType
		rsv.PathEndProps = req.PathProps
		rsv.TrafficSplit = req.SplitCls
		rsv.PathAtSource = req.Path // opaque for all AS but the source AS
		// we are going to extend a bit the information in the path of this reservation: if this
		// AS is at the beginning of the path or at the end, we can annotate the opaque path with
		// our IA id:
		rsv.PathAtSource.Steps[rsv.PathAtSource.CurrentStep].IA = s.localIA
	}

	req.Reservation = rsv

	if err := req.ValidateForReservation(rsv); err != nil {
		failedResponse.Message = "error validating request with reservation: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}

	// compute admission max BW
	err = s.admitter.AdmitRsv(ctx, tx, req)
	if err != nil {
		log.Debug("segment not admitted here", "id", req.ID.String(), "err", err)
		failedResponse.Message = "segment not admitted: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}
	// admitted; the request contains already the value inside the "allocation beads" of the rsv
	allocBW := req.AllocTrail[len(req.AllocTrail)-1].AllocBW
	log.Info("COLIBRI admission successful", "id", req.ID.String(), "idx", req.Index,
		"alloc", allocBW, "trail", req.AllocTrail)

	idx, err := rsv.NewIndex(req.Index, req.ExpirationTime, req.MinBW, req.MaxBW, allocBW,
		req.RLC, req.Reservation.PathType)
	if err != nil {
		err := s.errWrapStr("cannot create new index", err)
		failedResponse.Message = err.Error()
		return updateResponse(failedResponse)
	}
	index := rsv.Index(idx)

	res := &segment.SegmentSetupResponseSuccess{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Path.Steps)-1),
		},
	}
	if req.IsLastAS() {
		res.Token = *index.Token
	} else {
		// forward the request to the next COLIBRI service
		downstreamRes, err := s.getTokenFromDownstreamAdmission(ctx, req)
		if err != nil {
			failedResponse.Message = s.err(err).Error()
			return updateResponse(failedResponse)
		}
		if _, ok := downstreamRes.(*segment.SegmentSetupResponseFailure); ok {
			return updateResponse(downstreamRes)
		}
		success := downstreamRes.(*segment.SegmentSetupResponseSuccess)
		res.Authenticators = success.Authenticators
		log.Info("deleteme adding authenticators", "downstream", success.Authenticators, "here", res.Authenticators)
		res.Token = success.Token
	}

	// update token with new hop field
	step := req.Path.Steps[req.Path.CurrentStep]
	err = s.computeMAC(rsv.ID.Suffix, &res.Token, req.ID.ASID, req.ID.ASID, step.Ingress, step.Egress)
	if err != nil {
		failedResponse.Message = s.errWrapStr("cannot compute MAC", err).Error()
		return updateResponse(failedResponse)
	}

	// store token and colibri path inside reservation (rsv contains a pointer to `index`)
	index.Token = &res.Token
	index.AllocBW = res.Token.BWCls // could have been admitted for less downstream

	if err := tx.PersistSegmentRsv(ctx, rsv); err != nil {
		failedResponse.Message = "storing token, cannot persist rsv: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}
	if err := tx.Commit(); err != nil {
		failedResponse.Message = "storing token, cannot commit transaction: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}

	if !req.IsFirstAS() {
		err = s.authenticator.ComputeSegmentSetupResponseMAC(ctx, res, req.Path)
	}

	return res, err
}

func (s *Store) getTokenFromDownstreamAdmission(ctx context.Context, req *segment.SetupReq) (
	segment.SegmentSetupResponse, error) {

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeSegmentSetupRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. setup authenticator", err)
	}

	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		log.Debug("error finding a colibri service client", "err", err)
		return nil, serrors.WrapStr("while finding a colibri service client", err)
	}

	pbReq, err := translate.PBufSetupReq(req)
	if err != nil {
		return nil, serrors.WrapStr("translation failed", err)
	}
	pbRes, err := client.SegmentSetup(ctx, pbReq)
	if err != nil {
		return nil, serrors.WrapStr("forwarded request failed", err)
	}
	return translate.SetupResponse(pbRes)
}

// sendUpstreamForAdmission sends the request upstream until it reaches the last node in the
// path; the request's traveling path is then reversed and a normal admission is computed from this
// node until the end node of the reversed path (which is the source of a down segment request).
func (s *Store) sendUpstreamForAdmission(ctx context.Context, req *segment.SetupReq) (
	segment.SegmentSetupResponse, error) {

	// TODO(juagargi) this assert will fail: sendUpstreamForAdmission is called with
	// req.ReverseTraveling==false for core ASes.
	assert(req.ReverseTraveling,
		"sendUpstreamForAdmission must only be called for reverse traveling")

	failedResponse := &segment.SegmentSetupResponseFailure{
		FailedRequest: req,
	}

	if req.IsLastAS() {
		req.ReverseTraveling = false
		if err := req.Path.Reverse(); err != nil {
			failedResponse.Message = "cannot reverse path at first node in reverse trip: " +
				err.Error()
			return failedResponse, err
		}
		err := s.authenticator.ComputeSegmentSetupRequestInitialMAC(ctx, req)
		if err != nil {
			return nil, err
		}

		return s.admitSegmentReservation(ctx, req)
	}
	// forward to next colibri service upstream
	client, err := s.operator.ColibriClient(ctx, req.Path)
	if err != nil {
		return failedResponse, s.errWrapStr("while finding a colibri service client", err)
	}

	pbReq, err := translate.PBufSetupReq(req)
	if err != nil {
		return failedResponse, s.errWrapStr("translation failed", err)
	}
	pbRes, err := client.SegmentSetup(ctx, pbReq)
	if err != nil {
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res, err := translate.SetupResponse(pbRes)
	if err != nil {
		return nil, serrors.WrapStr("translating response", err)
	}
	if !req.IsFirstAS() {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeSegmentSetupResponseMAC(ctx, res, req.Path); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}

	// at this point, the reservation has been accepted. Update the request link with it:
	req.Reservation, err = s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		log.Error("reloading the admitted reservation", "err", err)
		return nil, serrors.WrapStr("reloading the admitted reservation", err)
	}

	return res, nil
}

func (s *Store) computeMAC(suffix []byte, tok *reservation.Token, srcAS, dstAS addr.AS,
	ingress, egress uint16) error {

	hf := tok.AddNewHopField(&reservation.HopField{
		Ingress: ingress,
		Egress:  egress,
	})
	isE2E := tok.InfoField.PathType == reservation.E2EPath
	return computeMAC(hf.Mac[:], s.colibriKey, suffix, tok, hf, srcAS, dstAS, isE2E)
}

// computeMAC returns the MAC into buff, which has to be at least 4 bytes long (or runtime panic).
func computeMAC(buff []byte,
	key, suffix []byte, tok *reservation.Token, hf *reservation.HopField,
	srcAS, dstAS addr.AS, isE2E bool) error {

	var input [colibri.LengthInputDataRound16]byte
	colibri.MACInputStatic(input[:], suffix, uint32(tok.InfoField.ExpirationTick), tok.BWCls,
		tok.RLC, !isE2E, false, tok.Idx, srcAS, dstAS, hf.Ingress, hf.Egress)
	return colibri.MACStaticFromInput(buff, key, input[:])
}

// obtainRsvs will query the local DB if the src is local, or dial the corresponding col service.
// Note that the returned slice could be empty if no segments could reach the destination.
func (s *Store) obtainRsvs(ctx context.Context, src, dst addr.IA, pathType reservation.PathType) (
	[]*colibri.ReservationLooks, error) {

	if src == s.localIA {
		segs, err := s.db.GetSegmentRsvsFromSrcDstIA(ctx, src, dst, pathType)
		if err != nil {
			return nil, serrors.WrapStr("getting reservations from db", err)
		}
		return reservationsToLooks(segs, s.localIA), nil
	}
	client, err := s.operator.DialSvcCOL(ctx, &src)
	if err != nil {
		return nil, serrors.WrapStr("dialing to list reservations from remote to remote", err,
			"src", src.String(), "dst", dst.String())
	}
	res, err := client.ListReservations(ctx, &colpb.ListReservationsRequest{
		DstIa:    uint64(dst),
		PathType: uint32(pathType),
	})
	if res.GetErrorMessage() != "" {
		err = fmt.Errorf(res.ErrorMessage)
	}
	if err != nil {
		return nil, serrors.WrapStr("listing reservations from remote to remote", err,
			"src", src.String(), "dst", dst.String())
	}
	return translate.ListResponse(res)
}

func sumAllBW(rsvs []*e2e.Reservation) uint64 {
	var accum uint64
	for _, r := range rsvs {
		accum += r.AllocResv()
	}
	return accum
}

func freeInSegRsv(ctx context.Context, tx backend.Transaction, segRsv *segment.Reservation) (
	uint64, error) {

	rsvs, err := tx.GetE2ERsvsOnSegRsv(ctx, &segRsv.ID)
	if err != nil {
		return 0, serrors.WrapStr("cannot obtain e2e reservations to compute free bw",
			err, "segment_id", segRsv.ID)
	}
	freeForData := float64(segRsv.ActiveIndex().AllocBW.ToKbps()) *
		segRsv.TrafficSplit.SplitForData()
	free := uint64(freeForData) - sumAllBW(rsvs)
	return free, nil
}

// max bw in egress interface of the transfer AS
func freeAfterTransfer(ctx context.Context, tx backend.Transaction, rsv *e2e.Reservation,
	renewal bool) (uint64, error) {

	seg1 := rsv.SegmentReservations[0]
	seg2 := rsv.SegmentReservations[1]
	if seg1.PathType == reservation.CorePath && seg2.PathType == reservation.DownPath {
		// as if no transfer
		return math.MaxUint64, nil
	}
	// get all seg rsvs with this AS as destination, AND transfer flag set
	rsvs, err := tx.GetAllSegmentRsvs(ctx)
	if err != nil {
		return 0, err
	}
	var total uint64 // all BW that ends up in this AS
	for _, r := range rsvs {
		if r.Egress == 0 && r.PathEndProps&reservation.EndTransfer != 0 {
			total += r.ActiveIndex().AllocBW.ToKbps()
		}
	}
	ratio := float64(seg1.ActiveIndex().AllocBW.ToKbps()) / float64(total)
	// effectiveE2eTraffic is the minimum BW that e2e rsvs can use
	effectiveE2eTraffic := float64(seg2.ActiveIndex().AllocBW.ToKbps()) * ratio

	e2es, err := tx.GetE2ERsvsOnSegRsv(ctx, &seg2.ID)
	if err != nil {
		return 0, err
	}
	alreadyUsed := int64(sumAllBW(e2es))
	if renewal {
		alreadyUsed -= int64(rsv.AllocResv()) // do not count this rsv's BW
	}
	// the available BW for this e2e rsv is the effective minus the already used
	avail := int64(effectiveE2eTraffic) - alreadyUsed
	if avail < 0 {
		log.Error("internal error: negative result in free after transfer",
			"ratio", ratio, "effective", effectiveE2eTraffic, "renewal", renewal,
			"already_used", alreadyUsed, "this_rsv_alloc", rsv.AllocResv())
		avail = 0
	}
	return uint64(avail), nil
}

func reservationsToLooks(rsvs []*segment.Reservation, localIA addr.IA) []*colibri.ReservationLooks {
	looks := make([]*colibri.ReservationLooks, len(rsvs))
	for i, r := range rsvs {
		looks[i] = &colibri.ReservationLooks{
			Id:        r.ID,
			SrcIA:     localIA,
			DstIA:     r.PathAtSource.DstIA(),
			Split:     r.TrafficSplit,
			PathSteps: r.PathAtSource.Steps,
		}
		if r.ActiveIndex() != nil {
			looks[i].ExpirationTime = r.ActiveIndex().Expiration
			looks[i].MinBW = r.ActiveIndex().MinBW
			looks[i].MaxBW = r.ActiveIndex().MaxBW
			looks[i].AllocBW = r.ActiveIndex().AllocBW
		}
	}
	return looks
}

// isFirstASInReservation indicates that an AS is the first AS in the path of the reservation.
// For up and core segments this is the first AS in the request as well.
// For down segments the first AS in the reservation will be the last AS in the request path,
// as the request travels in reverse until this last AS, and from there a "regular" setup is done.
func isFirstASInReservation(rsv *segment.Reservation, req *base.Request) bool {
	switch rsv.PathType {
	case reservation.UpPath, reservation.CorePath:
		return req.IsFirstAS()
	case reservation.DownPath:
		return req.IsLastAS()
	default:
		panic(fmt.Sprintf("unknown path type %v", rsv.PathType))
	}
}

func newTransparentPathFromReservation(rsv *segment.Reservation) (*base.TransparentPath, error) {
	colp := rsv.DeriveColibriPathAtSource()
	if rsv.ActiveIndex() == nil {
		return nil, serrors.New("no active index in reservation", "id", rsv.ID)
	}
	if !rsv.ActiveIndex().Expiration.After(time.Now()) {
		return nil, serrors.New("reservations has expired active index", "id", rsv.ID,
			"expiration", rsv.ActiveIndex().Expiration)
	}
	return &base.TransparentPath{
		CurrentStep: rsv.PathAtSource.CurrentStep,
		Steps:       rsv.PathAtSource.Steps,
		RawPath:     colp,
	}, nil
}

// assert performs an assertion on an invariant. An assertion is part of the documentation.
// TODO(juagargi) remove after finishing debugging COLIBRI
func assert(cond bool, msg string, params ...interface{}) {
	if !cond {
		panic(fmt.Sprintf(msg, params...))
	}
}
