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
	"crypto/cipher"
	"encoding/hex"
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
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
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
	colibriKey    cipher.Block                    // colibri secret key
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(
	topo *topology.Loader,
	operator *coliquic.ServiceClientOperator,
	tcpDialer libgrpc.Dialer,
	db backend.DB,
	admitter admission.Admitter,
	masterKey []byte) (
	*Store, error) {

	// check that the admitter is well configured
	cap := admitter.Capacities()
	for _, ifid := range append(topo.InterfaceIDs(), 0) {
		log.Info("colibri admission capacity", "ifid", ifid,
			"ingress", cap.CapacityIngress(uint16(ifid)),
			"egress", cap.CapacityEgress(uint16(ifid)))
	}
	colibriKeyBytes := scrypto.DeriveColibriMacKey(masterKey)
	colibriKey, err := libcolibri.InitColibriKey(colibriKeyBytes)
	if err != nil {
		return nil, err
	}
	return &Store{
		localIA:       topo.IA(),
		isCore:        topo.Core(),
		db:            db,
		admitter:      admitter,
		operator:      operator,
		authenticator: NewDRKeyAuthenticator(topo.IA(), tcpDialer),
		colibriKey:    colibriKey,
	}, nil
}

func (s *Store) Ready() bool {
	return s.operator.Initialized()
}

func (s *Store) err(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("@%s: %v", s.localIA, err)
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

func (s *Store) GetReservationsAtSource(ctx context.Context) (
	[]*segment.Reservation, error) {

	return s.db.GetSegmentRsvsFromSrcDstIA(ctx, s.localIA, 0, reservation.UnknownPath)
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
		Up:    make([]*colibri.SegRDetails, 0),
		Core:  make([]*colibri.SegRDetails, 0),
		Down:  make([]*colibri.SegRDetails, 0),
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
	if req.ID.IsEmpty() {
		return s.errNew("bad empty ID")
	}
	if req.ID.ASID != s.localIA.AS() {
		return s.errNew("bad reservation id", "as", req.ID.ASID)
	}

	newSetup := req.ID.IsEmptySuffix()
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
		"id", req.ID.String(), "idx", req.Index, "dst_ia", req.Steps.DstIA(), "path", req.Steps)

	origSteps := req.Steps.Copy()
	reverseTraveling := req.ReverseTraveling
	rollbackChanges := func(setupRes segment.SegmentSetupResponse) {
		// TODO(juagargi) allow to unit test this
		if failure, ok := setupRes.(*segment.SegmentSetupResponseFailure); ok {
			if !reverseTraveling {
				if len(failure.FailedRequest.AllocTrail)+1 < len(origSteps) {
					// shorten the path to exclude those nodes the request never transited.
					// the last node in allocTrail could (or not) have stored the index and
					// thus would need cleaning.
					origSteps = origSteps[:len(failure.FailedRequest.AllocTrail)+1]
				}
			}
		}
		if len(origSteps) < 2 {
			// only this AS to contact (or not even here), just don't send any RPC
			return
		}
		// uses the `baseReq` that will have the new ID and index, but the original path
		baseReq := base.NewRequest(req.Timestamp, &req.ID, req.Index, len(origSteps))
		var res base.Response
		var err error
		if newSetup {
			res, err = s.InitTearDownSegmentReservation(ctx, baseReq, origSteps, req.Transport())
		} else {
			res, err = s.InitCleanupSegmentReservation(ctx, baseReq, origSteps, req.Transport())
		}
		if err != nil {
			log.Info("while cleaning reservations down the path an error occurred",
				"new_setup", newSetup, "err", err, "res", res)
		} else if _, ok := res.(*base.ResponseSuccess); !ok {
			log.Info("while cleaning reservations down the path, received failure response",
				"new_setup", newSetup, "res", res)
		}
		if newSetup {
			if err := s.db.DeleteSegmentRsv(ctx, &rsv.ID); err != nil {
				log.Info("error removing unfinished reservation")
			}
		}
		log.Debug("reservation has been rollback", "new_setup", newSetup)
	}
	// create new reservation in DB
	if rsv == nil { // new setup
		rsv = segment.NewReservation(req.ID.ASID)
		rsv.ID = req.ID
		rsv.PathType = req.PathType
		rsv.PathEndProps = req.PathProps
		rsv.TrafficSplit = req.SplitCls
		rsv.Steps = req.Steps
		rsv.CurrentStep = req.CurrentStep
		rsv.TransportPath = req.TransportPath

		if err := s.db.NewSegmentRsv(ctx, rsv); err != nil {
			return s.errWrapStr("initial reservation creation", err, "dst", rsv.Steps.DstIA())
		}
		req.ID = rsv.ID // the DB created a new suffix for the rsv.; copy it to the request
	}

	var res segment.SegmentSetupResponse
	if req.PathType == reservation.DownPath {
		if s.isCore {
			return serrors.New("error initiating down path reservation: this is a core AS")
		}
		// reverse_traveling must be true iff this is a down rsv.
		// The flag indicates the admission to send the request to
		// the last AS of the path to re-start the request process from there, as the
		// admission must be computed in the direction of the reservation.
		req.ReverseTraveling = true
		res, err = s.sendUpstreamForAdmission(ctx, req)
	} else {
		err = s.authenticator.ComputeSegmentSetupRequestInitialMAC(ctx, req)
		if err != nil {
			return err
		}
		res, err = s.admitSegmentReservation(ctx, req)
	}
	if err != nil {
		log.Info("error initializing reservation", "id", rsv.ID.String(), "err", err)
		rollbackChanges(res)
		return err
	}
	if _, ok := res.(*segment.SegmentSetupResponseSuccess); !ok {
		rollbackChanges(res)
		return serrors.New("error in setup", "response", res)
	}
	rsv = req.Reservation

	// TODO(juagargi) deprecate the use of ReverseTraveling and all the complexity that it involves.
	if req.PathType != reservation.DownPath {
		ok, err := s.authenticator.ValidateSegmentSetupResponse(ctx, res, rsv.Steps)
		if !ok || err != nil {
			return s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	}

	// the initiator of the reservation (destination if down path, source otherwise) always
	// needs the colibri path ready; we must extract it from the returned response:
	resOk := res.(*segment.SegmentSetupResponseSuccess)
	idx := rsv.Index(resOk.Token.Idx)
	idx.Token = &resOk.Token
	idx.AllocBW = resOk.Token.BWCls
	if err := s.db.PersistSegmentRsv(ctx, rsv); err != nil {
		log.Info("error persisting reservation", "err", err)
		rollbackChanges(resOk)
	}

	return nil
}

// InitConfirmSegmentReservation needs the steps variable in the order of transport: this means
// in the direction of the SegR if core or up path, but reverse direction if down path.
func (s *Store) InitConfirmSegmentReservation(ctx context.Context, req *base.Request,
	steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req, steps); err != nil {
		return nil, serrors.WrapStr("initializing confirm segment reservation", err)
	}
	return s.ConfirmSegmentReservation(ctx, req, transport)

}

// InitActivateSegmentReservation needs the steps variable in the order of transport: this means
// in the direction of the SegR if core or up path, but reverse direction if down path.
func (s *Store) InitActivateSegmentReservation(ctx context.Context, req *base.Request,
	steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req, steps); err != nil {
		return nil, serrors.WrapStr("initializing activate segment reservation", err)
	}
	return s.ActivateSegmentReservation(ctx, req, transport)
}

func (s *Store) InitCleanupSegmentReservation(ctx context.Context, req *base.Request,
	steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req, steps); err != nil {
		return nil, serrors.WrapStr("initializing clean segment reservation", err)
	}
	return s.CleanupSegmentReservation(ctx, req, transport)
}

func (s *Store) InitTearDownSegmentReservation(ctx context.Context, req *base.Request,
	steps base.PathSteps, transport *colpath.ColibriPathMinimal) (
	base.Response, error) {

	// authenticate request
	if err := s.authenticator.ComputeRequestInitialMAC(ctx, req, steps); err != nil {
		return nil, serrors.WrapStr("initializing teardown segment reservation", err)
	}
	return s.TearDownSegmentReservation(ctx, req, transport)
}

func (s *Store) ListReservations(ctx context.Context, dstIA addr.IA,
	pathType reservation.PathType) ([]*colibri.SegRDetails, error) {
	rsvs, err := s.db.GetSegmentRsvsFromSrcDstIA(ctx, s.localIA, dstIA, pathType)
	if err != nil {
		log.Info("error listing reservations", "err", err)
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
func (s *Store) AdmitSegmentReservation(
	ctx context.Context,
	req *segment.SetupReq,
) (segment.SegmentSetupResponse, error) {

	if req.ReverseTraveling {
		return s.sendUpstreamForAdmission(ctx, req)
	}
	if err := s.authenticateSegSetupReq(ctx, req, req.CurrentStep); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}
	return s.admitSegmentReservation(ctx, req)
}

func newFailedMessage(req *base.Request, currentStep int) *base.ResponseFailure {
	return &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Authenticators)),
		},
		FailedStep: uint8(currentStep),
	}
}

// ConfirmSegmentReservation changes the state of an index from temporary to confirmed.
// TODO(juagargi) this RPC travels in reverse in the case of a down path: if a down-path SegR
// A<-B-<-C is initiated/triggered at A, the authenticators are computed at A, and validated
// at B and C.
func (s *Store) ConfirmSegmentReservation(
	ctx context.Context,
	req *base.Request,
	transport *colpath.ColibriPathMinimal,
) (base.Response, error) {

	// TODO: pack the common code to this segment-related functions
	if req.ID.ASID == 0 {
		return nil, serrors.New("bad AS id in request")
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()
	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return nil, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		return nil, serrors.New("no reservation found")
	}

	patchColibriTransport(transport, rsv.Steps)

	currentStep := rsv.CurrentStep
	steps := rsv.Steps
	egress := rsv.Egress()
	// because canonical storage of steps and current step is always in the direction of the
	// reservation, reverse them if we are traveling in the reverse direction:
	if rsv.PathType == reservation.DownPath {
		currentStep = len(rsv.Steps) - 1 - rsv.CurrentStep
		steps = rsv.Steps.Reverse()
		egress = rsv.Ingress()
	}

	failedResponse := newFailedMessage(req, currentStep)
	if err := req.Validate(steps); err != nil {
		failedResponse.Message = fmt.Sprintln("error validating request",
			"err", err.Error())
		return failedResponse, nil
	}

	if err := s.authenticateReq(ctx, steps.SrcIA(), req, currentStep, steps); err != nil {
		if !(currentStep == 0) {
			if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
				steps.SrcIA(), currentStep); err != nil {
				return nil, serrors.WrapStr("authenticating response", err)
			}
		}
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
	if currentStep == len(steps)-1 {
		res = &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Authenticators)),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(), currentStep)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	} else {
		// authenticate request for the destination AS
		if err := s.authenticator.ComputeRequestTransitMAC(ctx, req, steps.DstIA(),
			currentStep, steps); err != nil {
			return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
		}

		// forward to next colibri service
		client, err := s.operator.ColibriClient(ctx, egress, transport)
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
			log.Debug("error dialing next colibri service",
				"egress", egress,
				"with_transport?", transport != nil,
				"err", err)
			return failedResponse, s.errWrapStr("forwarded request failed", err)
		}
		res = translate.Response(pbRes.Base)
		if currentStep == 0 {
			ok, err := s.authenticator.ValidateResponse(ctx, res, steps)
			if !ok || err != nil {
				return failedResponse, s.errNew("validation of response failed", "ok", ok,
					"err", err, "id", req.ID)
			}
		} else {
			// create authenticators before passing the response to the previous node in the path
			if err := s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(),
				currentStep); err != nil {
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
func (s *Store) ActivateSegmentReservation(
	ctx context.Context,
	req *base.Request,
	transport *colpath.ColibriPathMinimal,
) (base.Response, error) {

	log.Debug("activating segment index", "transport", transport.String())
	// TODO: pack the common code to this segment-related functions
	if req.ID.ASID == 0 {
		return nil, serrors.New("bad AS id in request")
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()
	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return nil, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		return nil, serrors.New("no reservation found")
	}

	patchColibriTransport(transport, rsv.Steps)

	currentStep := rsv.CurrentStep
	steps := rsv.Steps
	egress := rsv.Egress()
	// because canonical storage of steps and current step is always in the direction of the
	// reservation, reverse them if we are traveling in the reverse direction:
	if rsv.PathType == reservation.DownPath {
		currentStep = len(rsv.Steps) - 1 - rsv.CurrentStep
		steps = rsv.Steps.Reverse()
		egress = rsv.Ingress()
	}

	failedResponse := newFailedMessage(req, currentStep)
	if !(currentStep == 0) {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
			steps.SrcIA(), currentStep); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if len(req.Authenticators) != len(steps)-1 {
		failedResponse.Message = fmt.Sprintln("inconsistent number of authenticators",
			"auth_count", len(req.Authenticators), "path_len", len(steps))
		return failedResponse, nil
	}
	if err := s.authenticateReq(ctx, steps.SrcIA(), req, currentStep, steps); err != nil {
		if !(currentStep == 0) {
			if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
				steps.SrcIA(), currentStep); err != nil {
				return nil, serrors.WrapStr("authenticating response", err)
			}
		}
		return failedResponse, nil
	}
	if err := rsv.SetIndexActive(req.Index); err != nil {
		return failedResponse, s.errWrapStr("cannot set index to active", err,
			"id", req.ID.String())
	}

	// TODO(juagargi) this should happen AFTER all valid responses
	if currentStep == 0 || rsv.CurrentStep == 0 {
		// This is the initiator or the source of the traffic. If down path, two ASes will store
		// the reservation tokens. In any other case, the initiator is the source of the traffic.
		// Because down path segments will be used by the initiator in the reverse direction of
		// the traffic to e.g. renew the segment, we must always store the tokens in the initiator.
		// Conversely we must also store the token in the source of the traffic, as any EER
		// that may be created by stitching the segment will need it in the source.
		var err error
		rsv.TransportPath, err = pathFromSegmentRsv(rsv)
		if err != nil {
			failedResponse.Message = s.errWrapStr("error obtaining colibri path from reservation",
				err).Error()
			return failedResponse, nil
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

	if currentStep == len(steps)-1 {
		// this is the last AS in the trip, initiate the response
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Authenticators)),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(), currentStep)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// this is not the last AS, prepare to send to next AS: authenticate request for
	// the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req, steps.DstIA(),
		currentStep, steps); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, egress, transport)
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
		log.Debug("error dialing next colibri service",
			"egress", egress,
			"with_transport?", transport != nil,
			"err", err)
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)

	if currentStep == 0 {
		ok, err := s.authenticator.ValidateResponse(ctx, res, steps)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(),
			currentStep); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// CleanupSegmentReservation deletes an index from a segment reservation.
func (s *Store) CleanupSegmentReservation(
	ctx context.Context,
	req *base.Request,
	transport *colpath.ColibriPathMinimal,
) (base.Response, error) {

	log.Debug("cleaning segment index up", "transport", transport.String())
	// TODO: pack the common code to this segment-related functions
	if req.ID.ASID == 0 {
		return nil, serrors.New("bad AS id in request")
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()
	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return nil, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		return nil, serrors.New("no reservation found")
	}

	patchColibriTransport(transport, rsv.Steps)

	currentStep := rsv.CurrentStep
	steps := rsv.Steps
	egress := rsv.Egress()
	// because canonical storage of steps and current step is always in the direction of the
	// reservation, reverse them if we are traveling in the reverse direction:
	if rsv.PathType == reservation.DownPath {
		currentStep = len(rsv.Steps) - 1 - rsv.CurrentStep
		steps = rsv.Steps.Reverse()
		egress = rsv.Ingress()
	}

	failedResponse := newFailedMessage(req, currentStep)
	if !(currentStep == 0) {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
			steps.SrcIA(), currentStep); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if len(req.Authenticators) != len(steps)-1 {
		failedResponse.Message = fmt.Sprintln("inconsistent number of authenticators",
			"auth_count", len(req.Authenticators), "path_len", len(steps))
		return failedResponse, nil
	}
	if err := s.authenticateReq(ctx, steps.SrcIA(), req, currentStep, steps); err != nil {
		if !(currentStep == 0) {
			if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
				steps.SrcIA(), currentStep); err != nil {
				return nil, serrors.WrapStr("authenticating response", err)
			}
		}
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

	if currentStep == len(steps)-1 {
		// this is the last AS in the trip, initiate the response
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Authenticators)),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(), currentStep)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// this is not the last AS, prepare to send to next AS: authenticate request for
	// the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req, steps.DstIA(),
		currentStep, steps); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, egress, transport)
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
		log.Debug("error dialing next colibri service",
			"egress", egress,
			"with_transport?", transport != nil,
			"err", err)
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if currentStep == 0 {
		ok, err := s.authenticator.ValidateResponse(ctx, res, steps)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(),
			currentStep); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// TearDownSegmentReservation removes a whole segment reservation.
func (s *Store) TearDownSegmentReservation(
	ctx context.Context,
	req *base.Request,
	transport *colpath.ColibriPathMinimal,
) (base.Response, error) {

	// TODO: pack the common code to this segment-related functions

	if req.ID.ASID == 0 {
		return nil, serrors.New("bad AS id in request")
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, s.errWrapStr("cannot create transaction", err, "id", req.ID.String())
	}
	defer tx.Rollback()
	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return nil, s.errWrapStr("cannot obtain segment reservation", err,
			"id", req.ID.String())
	}
	if rsv == nil {
		return nil, serrors.New("no reservation found")
	}

	patchColibriTransport(transport, rsv.Steps)

	currentStep := rsv.CurrentStep
	steps := rsv.Steps
	egress := rsv.Egress()
	if rsv.PathType == reservation.DownPath {
		currentStep = len(rsv.Steps) - 1 - rsv.CurrentStep
		steps = rsv.Steps.Reverse()
		egress = rsv.Ingress()
	}
	failedResponse := newFailedMessage(req, currentStep)
	if !(currentStep == 0) {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
			steps.SrcIA(), currentStep); err != nil {
			return nil, serrors.WrapStr("authenticating response", err)
		}
	}
	if len(req.Authenticators) != len(steps)-1 {
		failedResponse.Message = fmt.Sprintln("inconsistent number of authenticators",
			"auth_count", len(req.Authenticators), "path_len", len(steps))
		return failedResponse, nil
	}
	if err := s.authenticateReq(ctx, steps.SrcIA(), req, currentStep, steps); err != nil {
		if !(currentStep == 0) {
			if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
				steps.SrcIA(), currentStep); err != nil {
				return nil, serrors.WrapStr("authenticating response", err)
			}
		}
		return failedResponse, nil
	}
	if err := tx.DeleteSegmentRsv(ctx, &req.ID); err != nil {
		return failedResponse, s.errWrapStr("cannot teardown reservation", err,
			"id", req.ID.String())
	}

	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}

	if currentStep >= len(steps)-1 {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Authenticators)),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res,
			steps.SrcIA(), currentStep)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeRequestTransitMAC(ctx, req, steps.DstIA(), currentStep,
		steps); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. authenticator", err)
	}
	// forward to next colibri service
	client, err := s.operator.ColibriClient(ctx, egress, transport)
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
		log.Debug("error dialing next colibri service",
			"egress", egress,
			"with_transport?", transport != nil,
			"err", err)
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if currentStep == 0 {
		ok, err := s.authenticator.ValidateResponse(ctx, res, steps)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, steps.SrcIA(),
			currentStep); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// AdmitE2EReservation will attempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(
	ctx context.Context,
	req *e2e.SetupReq,
	transport *colpath.ColibriPathMinimal,
) (e2e.SetupResponse, error) {

	log.Debug(
		"e2e admission request",
		"id", req.ID,
		"currentStep", req.CurrentStep,
		"steps", req.Steps,
		"segments", reservation.IDs(req.SegmentRsvs),
		"curr_segment", req.CurrentSegmentRsvIndex,
	)

	if err := s.authenticateE2ESetupReq(ctx, req); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	failedResponse := &e2e.SetupResponseFailure{
		FailedStep: uint8(req.CurrentStep),
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
		log.Info("error retrieving e2e reservation", "err", err)
		return failedResponse, err
	}
	newSetup := (rsv == nil)
	if newSetup {
		rsv = &e2e.Reservation{
			ID:                  req.ID,
			Steps:               req.Steps,
			CurrentStep:         req.CurrentStep,
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

		// TODO(juagargi) do the shortcut checking here:
		// When an endhost receives the list of segment details, it stitches the segment and then
		// removes duplicated ASes in the path. Since the modified path is not part of the original
		// segments that the ASes have published, the ASes have the opportunity to allow or deny
		// the admission based on some criteria here.

		// This is the only moment where we need to validate req.Steps against the segments.Steps.
		// After this, we will store the rsv.Steps built from req.Steps and not touch them again
		if err := validateE2ESteps(s.localIA, rsv, req.Steps, req.CurrentStep); err != nil {
			failedResponse.Message = err.Error()
			return failedResponse, err
		}
	} else {
		// not a new setup
		if index := rsv.Index(req.Index); index != nil {
			// renewal with index clash
			failedResponse.Message = s.errNew("already existing e2e index", "id", req.ID.String(),
				"idx", req.Index).Error()
			return failedResponse, nil
		}
		assert(len(rsv.SegmentReservations) < 3, "logic error, too many segments in AS. ID: %s, "+
			"seg. ids: %s", req.ID, req.SegmentRsvs)
	}

	// validate the steps in the request against those stored in the reservation
	if !rsv.Steps.Equal(req.Steps) {
		err = serrors.New("request and reservation steps differ",
			"req_steps", req.Steps.String(), "rsv_steps", rsv.Steps.String())
		failedResponse.Message = err.Error()
		return failedResponse, err
	}

	isStitchPoint := rsv.IsStitchPoint(s.localIA)
	if isStitchPoint {
		assert(len(rsv.SegmentReservations) == 2, "logic error: too many segments in AS: %v",
			rsv.SegmentReservations)
		assert(rsv.SegmentReservations[0].Steps.DstIA().Equal(s.localIA),
			"logic error: incoming segment in transfer node doesn't end here. Segs: %s, "+
				"first segment: %s, second segment: %s", req.SegmentRsvs,
			rsv.SegmentReservations[0].Steps,
			rsv.SegmentReservations[1].Steps)
	}

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

	if isStitchPoint {
		freeOutgoing, err := freeAfterTransfer(ctx, tx, rsv, !newSetup)
		if err != nil {
			failedResponse.Message = s.errWrapStr("cannot compute transfer", err,
				"id", req.ID).Error()
			return failedResponse, nil
		}
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
	res := &e2e.SetupResponseSuccess{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp: req.Timestamp,
		},
	}

	// Check dataplane path
	if err := rsv.Steps.ValidateEquivalent(transport, rsv.CurrentStep); err != nil {
		return nil, err
	}

	var ingress, egress uint16
	if req.IsLastAS() {
		var notAdmittedMsg string
		if admitted {
			// check white/black (admission) list of endhost
			admitted = false
			res, err := tx.CheckAdmissionList(ctx, time.Now(), req.DstHost,
				rsv.Steps.SrcIA(), req.SrcHost.String())
			log.Debug(
				"checked admission list",
				"admit", res,
				"err", err,
				"host", req.DstHost.String(),
				"src_ia", rsv.Steps.SrcIA(),
				"src_host", req.SrcHost,
			)
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
		ingress = rsv.Ingress()
		egress = rsv.Egress()
		// all ASes in the path will create authenticators for the initiator end-host
		res.Authenticators = make([][]byte, len(rsv.Steps)) // same size as path
		token = index.Token
	} else { // this is not the last AS
		if s.localIA.Equal(rsv.Steps.SrcIA()) {
			r, err := tx.GetSegmentRsvFromID(ctx, &req.SegmentRsvs[req.CurrentSegmentRsvIndex])
			if err != nil {
				return nil, err
			}
			transport = r.DeriveColibriPathAtSource()
		} else if isStitchPoint {
			req.CurrentSegmentRsvIndex++
			rNext, err := tx.GetSegmentRsvFromID(ctx, &req.SegmentRsvs[req.CurrentSegmentRsvIndex])
			if err != nil {
				return nil, err
			}
			transport = rNext.DeriveColibriPathAtSource()
		}
		ingress = rsv.Ingress()
		egress = rsv.Egress()
		// authenticate request for the destination AS
		if err := s.authenticator.ComputeE2ESetupRequestTransitMAC(ctx, req); err != nil {
			return nil, serrors.WrapStr("computing in transit e2e setup request authenticator", err)
		}
		// deleteme BUG here using a segR to contact the next colSrv when stitch point;
		// the bug is present also in E2E cleanup, maybe in some other segR RPC as well
		// client, err := s.operator.ColibriClient(ctx, egress, transportPath)
		client, err := s.operator.ColibriClient(ctx, egress, nil)
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
			log.Debug("error dialing next colibri service",
				"egress", egress,
				"with_transport?", transport != nil,
				"err", err)
			failedResponse.Message = s.errWrapStr("error forwarding request", err).Error()
			return failedResponse, nil
		}
		downstreamRes, err := translate.E2ESetupResponse(pbRes)
		if err != nil {
			return nil, serrors.WrapStr("translating response", err)
		}
		success, ok := downstreamRes.(*e2e.SetupResponseSuccess)
		if !ok {
			// not admitted
			return downstreamRes, nil
		}
		token, err = reservation.TokenFromRaw(success.Token)
		if err != nil {
			failedResponse.Message = s.errWrapStr("decoding token from node ahead", err).Error()
			return failedResponse, nil
		}
		res.Authenticators = success.Authenticators
	}
	// here the request was admitted and returning back from the down stream admission

	err = s.addHopFieldToColibriPath(rsv.ID.Suffix, token, req.ID.ASID, req.ID.ASID, ingress, egress)
	if err != nil {
		failedResponse.Message = s.errWrapStr("cannot compute MAC", err).Error()
		return failedResponse, err
	}

	index.Token = token // copy the link to the reservation
	if err := tx.PersistE2ERsv(ctx, rsv); err != nil {
		return failedResponse, s.errWrapStr("cannot persist e2e reservation", err,
			"id", req.ID.String())
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, s.errWrapStr("cannot commit transaction", err,
			"id", req.ID.String())
	}

	res.Token = token.ToRaw()

	// create authenticators before passing the response to the previous node in the path
	if err := s.authenticator.ComputeE2ESetupResponseMAC(ctx, res, req.CurrentStep,
		rsv.Steps.SrcIA(), addr.HostFromIP(req.SrcHost), &req.ID); err != nil {
		return failedResponse, s.errWrapStr("computing authenticators for response", err)
	}
	// return the token upstream
	return res, nil
}

// CleanupE2EReservation will remove an index from an e2e reservation.
func (s *Store) CleanupE2EReservation(
	ctx context.Context,
	req *e2e.Request,
	transport *colpath.ColibriPathMinimal,
) (base.Response, error) {

	log.Debug(
		"e2e cleanup request",
		"id", req.ID,
	)
	failedResponse := &base.ResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Authenticators)),
		},
		Message: "failed to cleanup e2e index",
	}
	rsv, err := s.db.GetE2ERsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, s.errWrapStr("obtaining e2e reservation", err,
			"id", req.ID.String())
	}

	failedResponse.FailedStep = uint8(rsv.CurrentStep)
	if err := s.authenticateE2EReq(ctx, req, rsv.Steps, rsv.CurrentStep); err != nil {
		return nil, s.errWrapStr("error validating request", err, "id", req.ID.String())
	}

	if !rsv.IsFirstAS() {
		if err := s.authenticator.ComputeResponseMAC(ctx, failedResponse,
			rsv.Steps.SrcIA(), rsv.CurrentStep); err != nil {

			return nil, serrors.WrapStr("authenticating response", err)
		}
	}

	if err := req.Validate(rsv.Steps); err != nil {
		failedResponse.Message = "request validation failed: " + s.err(err).Error()
		return failedResponse, nil
	}

	isTransfer := false
	if len(rsv.SegmentReservations) > 1 {
		isTransfer = true
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, s.errWrapStr("cannot create transaction", err,
			"id", req.ID.String())
	}
	defer tx.Rollback()
	// Check dataplane path
	if err := rsv.Steps.ValidateEquivalent(transport, rsv.CurrentStep); err != nil {
		return nil, err
	}
	// deleteme TODO(juagargi) review the need(less) of calling DeriveColibriPath here (and in other functions in Store)
	if s.localIA.Equal(rsv.Steps.SrcIA()) || isTransfer {
		if s.localIA.Equal(rsv.Steps.SrcIA()) {
			r, err := tx.GetSegmentRsvFromID(ctx, &rsv.SegmentReservations[0].ID)
			if err != nil {
				return nil, err
			}
			transport = r.DeriveColibriPathAtSource()
		} else {
			r, err := tx.GetSegmentRsvFromID(ctx, &rsv.SegmentReservations[1].ID)
			if err != nil {
				return nil, err
			}
			transport = r.DeriveColibriPathAtSource()
		}
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
		log.Debug("e2e cleanup successful", "id", req.ID, "steps", rsv.Steps,
			"currentStep", rsv.CurrentStep)
	}

	if rsv.IsLastAS() {
		res := &base.ResponseSuccess{
			AuthenticatedResponse: base.AuthenticatedResponse{
				Timestamp:      req.Timestamp,
				Authenticators: make([][]byte, len(req.Authenticators)),
			},
		}
		err = s.authenticator.ComputeResponseMAC(ctx, res, rsv.Steps.SrcIA(), rsv.CurrentStep)
		if err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
		return res, nil
	}
	// authenticate the semi mutable parts of the request, to be validated at the destination
	if err := s.authenticator.ComputeE2ERequestTransitMAC(ctx, req, rsv.Steps,
		rsv.CurrentStep); err != nil {

		return nil, serrors.WrapStr("computing in transit e2e base request authenticator", err)
	}
	// forward to next colibri service
	// deleteme BUG using transportPath when this is a stitching point. Also present in E2ESetup
	// client, err := s.operator.ColibriClient(ctx, rsv.Steps[rsv.CurrentStep].Egress, transportPath)
	client, err := s.operator.ColibriClient(ctx, rsv.Steps[rsv.CurrentStep].Egress, nil)
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
		log.Debug("error dialing next colibri service",
			"egress", rsv.Steps[rsv.CurrentStep].Egress,
			"with_transport?", transport != nil,
			"err", err)
		return failedResponse, s.errWrapStr("forwarded request failed", err)
	}
	res := translate.Response(pbRes.Base)
	if rsv.IsFirstAS() {
		ok, err := s.authenticator.ValidateResponse(ctx, res, rsv.Steps)
		if !ok || err != nil {
			return failedResponse, s.errNew("validation of response failed", "ok", ok, "err", err,
				"id", req.ID)
		}
	} else {
		// create authenticators before passing the response to the previous node in the path
		if err := s.authenticator.ComputeResponseMAC(ctx, res, rsv.Steps.SrcIA(),
			rsv.CurrentStep); err != nil {
			return failedResponse, s.errWrapStr("computing authenticators for response", err)
		}
	}
	return res, nil
}

// DeleteExpiredIndices will just call the DB's method to delete the expired indices.
func (s *Store) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, time.Time, error) {
	n, err := s.db.DeleteExpiredIndices(ctx, now)
	if err != nil {
		return 0, time.Time{}, err
	}
	exp, err := s.db.NextExpirationTime(ctx)
	// we will return the next expiration time as earliest(now+16 , exp)
	if exp.After(time.Now().Add(reservation.E2ERsvDuration)) {
		exp = time.Now().Add(reservation.E2ERsvDuration)
	}
	return n, exp, err
}

// authenticateReq checks that the authenticators are correct.
func (s *Store) authenticateReq(ctx context.Context, remote addr.IA, req *base.Request,
	currentStep int, steps base.PathSteps) error {
	if currentStep == 0 {
		return nil
	}
	ok, err := s.authenticator.ValidateRequest(ctx, remote, req, currentStep, steps)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// authenticateSegSetupReq checks that the authenticators are correct.
func (s *Store) authenticateSegSetupReq(ctx context.Context, req *segment.SetupReq,
	currentStep int) error {
	ok, err := s.authenticator.ValidateSegSetupRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// validateE2ESteps checks that the current step obtained in the possible dual segment
// corresponds to that of the current step from the request steps.
func validateE2ESteps(localIA addr.IA, rsv *e2e.Reservation, reqSteps base.PathSteps,
	reqCurrStep int) error {

	isStitchPoint := rsv.IsStitchPoint(localIA)
	stitched := append(base.PathSteps{}, rsv.SegmentReservations[0].Steps...)
	for i := 1; i < len(rsv.SegmentReservations); i++ {
		s := rsv.SegmentReservations[i].Steps
		// no need to check: by standard s[0].Ingress == stitched[last].Egress == 0
		stitched[len(stitched)-1].Egress = s[0].Egress
		stitched = append(stitched, s[1:]...)
	}

	var currInStitched int
	prebuiltErr := serrors.New("steps validation error, request differs from segments",
		"local_ia", localIA,
		"stitched", stitched.String(), "stitch_curr", currInStitched, "stitch_point", isStitchPoint,
		"req_steps", reqSteps.String(), "req_curr_step", reqCurrStep)

	localASFound := false
	for ; currInStitched < len(rsv.SegmentReservations[0].Steps); currInStitched++ {
		if stitched[currInStitched].IA == localIA {
			if localASFound {
				return serrors.WrapStr("error: local AS found more than once in steps", prebuiltErr)
			}
			localASFound = true
			if stitched[currInStitched].Ingress == reqSteps[reqCurrStep].Ingress &&
				stitched[currInStitched].Egress == reqSteps[reqCurrStep].Egress {
				break
			}
		}
	}
	if !localASFound {
		return serrors.WrapStr("local AS not found", prebuiltErr)
	}

	assert(!isStitchPoint ||
		(currInStitched == len(rsv.SegmentReservations[0].Steps)-1 &&
			rsv.SegmentReservations[1].Steps[0].IA == localIA),
		"being a stitch point means being at the last AS of the first segment and "+
			"fist AS of the second segment. Details: %v", prebuiltErr)

	assert(stitched[currInStitched].IA == localIA, "bad local IA or curr step: %v", prebuiltErr)

	return nil
}

// authenticateE2EReq checks that the authenticators are correct.
func (s *Store) authenticateE2EReq(ctx context.Context, req *e2e.Request, steps base.PathSteps,
	currentStep int) error {

	ok, err := s.authenticator.ValidateE2ERequest(ctx, req, steps, currentStep)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

// authenticateE2ESetupReq checks that the authenticators are correct.
func (s *Store) authenticateE2ESetupReq(ctx context.Context, req *e2e.SetupReq) error {
	ok, err := s.authenticator.ValidateE2ESetupRequest(ctx, req)
	if err != nil {
		return serrors.WrapStr("validating source authentication mac", err)
	}
	if !ok {
		return serrors.New("source authentication invalid")
	}

	return nil
}

func (s *Store) admitSegmentReservation(
	ctx context.Context,
	req *segment.SetupReq,
) (segment.SegmentSetupResponse, error) {

	logger := log.FromCtx(ctx)

	failedResponse := &segment.SegmentSetupResponseFailure{
		AuthenticatedResponse: base.AuthenticatedResponse{
			Timestamp:      req.Timestamp,
			Authenticators: make([][]byte, len(req.Authenticators)),
		},
		FailedStep:    uint8(req.CurrentStep),
		FailedRequest: req,
	}
	updateResponse := func(res segment.SegmentSetupResponse) (segment.SegmentSetupResponse, error) {
		if !(req.CurrentStep == 0) {
			if err := s.authenticator.ComputeSegmentSetupResponseMAC(ctx, failedResponse,
				req.Steps, req.CurrentStep); err != nil {

				return nil, serrors.WrapStr("computing seg. setup response authentication", err)
			}
		}
		return res, nil
	}

	logger.Debug(
		"segment admission",
		"id", req.ID,
		"steps", req.Steps,
		"current", req.CurrentStep,
		"transported_by_colibri?", req.TransportPath != nil,
	)
	// Calling to req.Validate() also validates that ingress/egress from dataplane,
	// matches ingress/egress from req.Steps[req.CurrentStep]
	if err := req.Validate(s.operator.Neighbor); err != nil {
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
		rsv.PathType = req.PathType
		rsv.PathEndProps = req.PathProps
		rsv.TrafficSplit = req.SplitCls
		rsv.CurrentStep = req.CurrentStep
		rsv.Steps = req.Steps
		rsv.TransportPath = req.TransportPath
	}

	req.Reservation = rsv

	if err := req.ValidateForReservation(rsv); err != nil {
		failedResponse.Message = "error validating request with reservation: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}

	// compute admission max BW
	err = s.admitter.AdmitRsv(ctx, tx, req)
	if err != nil {
		logger.Debug("segment not admitted here", "id", req.ID.String(), "err", err)
		failedResponse.Message = "segment not admitted: " + s.err(err).Error()
		return updateResponse(failedResponse)
	}
	// admitted; the request contains already the value inside the "allocation beads" of the rsv
	allocBW := req.AllocTrail[len(req.AllocTrail)-1].AllocBW
	logger.Info("COLIBRI admission successful", "id", req.ID.String(), "idx", req.Index,
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
			Authenticators: make([][]byte, len(req.Authenticators)),
		},
	}
	// if this is the last step, create a token from the new empty index
	if req.CurrentStep == len(req.Steps)-1 {
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
		res.Token = success.Token
	}

	// update token with new hop field
	fmt.Printf("******************************deleteme **** %s\n", rsv.ID)
	fmt.Printf("existing hop fields: %d\n", len(res.Token.HopFields))
	if err = s.addHopFieldToColibriPath(rsv.ID.Suffix, &res.Token,
		rsv.Steps.SrcIA().AS(), rsv.Steps.DstIA().AS(), rsv.Ingress(), rsv.Egress()); err != nil {

		failedResponse.Message = s.errWrapStr("error computing MAC", err).Error()
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

	if req.CurrentStep != 0 {
		err = s.authenticator.ComputeSegmentSetupResponseMAC(ctx, res, req.Steps, req.CurrentStep)
	}

	return res, err
}

func (s *Store) getTokenFromDownstreamAdmission(
	ctx context.Context,
	req *segment.SetupReq,
) (segment.SegmentSetupResponse, error) {

	// authenticate request for the destination AS
	if err := s.authenticator.ComputeSegmentSetupRequestTransitMAC(ctx, req); err != nil {
		return nil, serrors.WrapStr("computing in transit seg. setup authenticator", err)
	}

	transport := req.Transport()
	patchColibriTransport(transport, req.Steps)

	client, err := s.operator.ColibriClient(ctx, req.Egress(), transport)
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
		log.Debug("error dialing next colibri service",
			"egress", req.Egress(),
			"with_transport?", req.TransportPath != nil,
			"err", err)
		return nil, serrors.WrapStr("forwarded request failed", err)
	}
	return translate.SetupResponse(pbRes)
}

// sendUpstreamForAdmission sends the request upstream until it reaches the last node in the
// path; the request's traveling path is then reversed and a normal admission is computed from this
// node until the end node of the reversed path (which is the source of a down segment request).
func (s *Store) sendUpstreamForAdmission(
	ctx context.Context,
	req *segment.SetupReq,
) (segment.SegmentSetupResponse, error) {

	log.Debug("climbing upstream for admission", "curr_step", req.CurrentStep, "steps", req.Steps)
	// TODO(juagargi) this assert will fail: sendUpstreamForAdmission is called with
	// req.ReverseTraveling==false for core ASes.
	assert(req.ReverseTraveling,
		"sendUpstreamForAdmission must only be called for reverse traveling")

	failedResponse := &segment.SegmentSetupResponseFailure{
		FailedRequest: req,
	}

	if req.CurrentStep == 0 {
		// this is the source of the traffic of the SegR, create the authenticators
		err := s.authenticator.ComputeSegmentSetupRequestInitialMAC(ctx, req)
		if err != nil {
			return nil, err
		}

		// and do regular admission
		req.ReverseTraveling = false
		// reverse path so we can now reach the previous sender
		req.TransportPath, err = req.TransportPath.ReverseAsColibri()
		if err != nil {
			log.Info("error reversing scion or colibri path", "err", err,
				"path", req.TransportPath)
		}
		return s.admitSegmentReservation(ctx, req)
	}

	transport := req.Transport()
	patchColibriTransport(transport, req.Steps)

	// if this is not the source of the traffic of the SegR (first step), then
	// forward to next colibri service upstream; note that because it travels in reverse,
	// the outbound traffic goes through the ingress interface in the request:
	client, err := s.operator.ColibriClient(ctx, req.Ingress(), transport)
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

	// at this point, the reservation has been accepted. Update the request link with it:
	req.Reservation, err = s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		log.Info("error reloading the admitted reservation", "err", err)
		return nil, serrors.WrapStr("reloading the admitted reservation", err)
	}

	return res, nil
}

func (s *Store) addHopFieldToColibriPath(suffix []byte, tok *reservation.Token, srcAS, dstAS addr.AS,
	ingress, egress uint16) error {

	hf := tok.AddNewHopField(&reservation.HopField{
		Ingress: ingress,
		Egress:  egress,
	})
	isE2E := tok.InfoField.PathType == reservation.E2EPath
	err := computeMAC(hf.Mac[:], s.colibriKey, suffix, tok, hf, srcAS, dstAS, isE2E)
	// deleteme
	fmt.Printf("in: %d, eg: %d, MAC: %s\n", hf.Ingress, hf.Egress, hex.EncodeToString(hf.Mac[:]))
	return err
}

// computeMAC returns the MAC into buff, which has to be at least 4 bytes long (or runtime panic).
func computeMAC(buff []byte, key cipher.Block, suffix []byte, tok *reservation.Token,
	hf *reservation.HopField, srcAS, dstAS addr.AS, isE2E bool) error {

	var input [libcolibri.LengthInputDataRound16]byte
	libcolibri.MACInputStatic(input[:], suffix, uint32(tok.InfoField.ExpirationTick), tok.BWCls,
		tok.RLC, !isE2E, false, tok.Idx, srcAS, dstAS, hf.Ingress, hf.Egress)
	return libcolibri.MACStaticFromInput(buff, key, input[:])
}

// obtainRsvs will query the local DB if the src is local, or dial the corresponding col service.
// Note that the returned slice could be empty if no segments could reach the destination.
func (s *Store) obtainRsvs(ctx context.Context, src, dst addr.IA, pathType reservation.PathType) (
	[]*colibri.SegRDetails, error) {

	if src == s.localIA {
		segs, err := s.db.GetSegmentRsvsFromSrcDstIA(ctx, src, dst, pathType)
		if err != nil {
			return nil, serrors.WrapStr("getting reservations from db", err)
		}
		return reservationsToLooks(segs, s.localIA), nil
	}
	client, err := s.operator.ColibriClientForIA(ctx, &src)
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
		if r.Egress() == 0 && r.PathEndProps&reservation.EndTransfer != 0 {
			total += r.ActiveIndex().AllocBW.ToKbps()
		}
	}
	ratio := float64(seg1.ActiveIndex().AllocBW.ToKbps()) / float64(total)
	// effectiveE2ETraffic is the minimum BW that e2e rsvs can use
	effectiveE2ETraffic := float64(seg2.ActiveIndex().AllocBW.ToKbps()) * ratio

	e2es, err := tx.GetE2ERsvsOnSegRsv(ctx, &seg2.ID)
	if err != nil {
		return 0, err
	}
	alreadyUsed := int64(sumAllBW(e2es))
	if renewal {
		alreadyUsed -= int64(rsv.AllocResv()) // do not count this rsv's BW
	}
	// the available BW for this e2e rsv is the effective minus the already used
	avail := int64(effectiveE2ETraffic) - alreadyUsed
	if avail < 0 {
		log.Info("error internal error: negative result in free after transfer",
			"ratio", ratio, "effective", effectiveE2ETraffic, "renewal", renewal,
			"already_used", alreadyUsed, "this_rsv_alloc", rsv.AllocResv())
		avail = 0
	}
	return uint64(avail), nil
}

func reservationsToLooks(rsvs []*segment.Reservation, localIA addr.IA) []*colibri.SegRDetails {
	looks := make([]*colibri.SegRDetails, len(rsvs))
	for i, r := range rsvs {
		looks[i] = &colibri.SegRDetails{
			Id:    r.ID,
			SrcIA: localIA,
			DstIA: r.Steps.DstIA(),
			Split: r.TrafficSplit,
			Steps: r.Steps,
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

func pathFromSegmentRsv(rsv *segment.Reservation) (*colpath.ColibriPathMinimal, error) {
	if rsv.ActiveIndex() == nil {
		return nil, serrors.New("no active index in reservation", "id", rsv.ID)
	}
	if !rsv.ActiveIndex().Expiration.After(time.Now()) {
		return nil, serrors.New("reservations has an expired active index", "id", rsv.ID,
			"expiration", rsv.ActiveIndex().Expiration)
	}
	if rsv.CurrentStep != 0 {
		// this must be the destination of a down-path segment
		assert(rsv.CurrentStep == len(rsv.Steps)-1, "path should be derived only at the source "+
			"of the traffic (any case) or at the initiator (down-path), which must be the "+
			"destination of the traffic. Details of the reservation: ID: %s, type: %s, "+
			"current_step: %d, steps: %s",
			rsv.ID, rsv.PathType, rsv.CurrentStep, rsv.Steps,
		)
		assert(rsv.PathType == reservation.DownPath, "path should be derived at the destination "+
			"only for down-path segments. Details of the reservation: ID: %s, type: %s, "+
			"current_step: %d, steps: %s",
			rsv.ID, rsv.PathType, rsv.CurrentStep, rsv.Steps,
		)
		return rsv.DeriveColibriPathAtDestination(), nil
	}
	return rsv.DeriveColibriPathAtSource(), nil
}

// patchColibriTransport is at temporary fix:
// We lost the information about the destination of the packet when we parsed
// the SCION layer. Now we can't recover it.
// But since the transport used for this RPC must be an index of the reservation, we know
// that the steps are the same as in the reservation.
// We further know that the destination has to be a colibri service.
// Fix those two fields.
func patchColibriTransport(transport *colpath.ColibriPathMinimal, steps base.PathSteps) {
	return
	// if transport == nil {
	// 	return
	// }
	// if !transport.InfoField.S {
	// 	// TODO(juagargi) obtain the destination address from the scion layer and pass it along
	// 	// embedded in the UDPAddr (other options?)
	// 	panic("this patch won't work for EERs")
	// }
	// // transport.Dst = *caddr.NewEndpointWithAddr(steps.DstIA(), addr.SvcCOL.Base())
}

// assert performs an assertion on an invariant. An assertion is part of the documentation.
// TODO(juagargi) remove after finishing debugging COLIBRI
func assert(cond bool, msg string, params ...interface{}) {
	if !cond {
		panic(fmt.Sprintf(msg, params...))
	}
}
