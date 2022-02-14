package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"time"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	pb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

var ErrMissingKey = serrors.New("Problem getting key for intermediate AS")

type ExtendedReservationManager interface {
	Store() reservationstorage.Store
	SetupRequest(ctx context.Context, req *segment.SetupReq) error
	DRKey(context.Context, *pb.DRKeyRequest) (*pb.DRKeyResponse, error)
	LookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (*colibri.ReservationLooks, error)
}

type DRKeyReq struct {
	Chain       []x509.Certificate // include certificate to check signature
	EphPubkey   []byte             // PubKey for deriving/encrypting DRKey message in KEM/DEM
	ValTime     time.Time
	SegmentRsvs []lib_res.ID
}

type Bootstrapper interface {
	// BootstrapKey(ctx context.Context, trip *colibri.FullTrip,
	// 	valTime time.Time) (*drkey.Lvl2Key, error)
	SendDRKeyReq(ctx context.Context, trip colibri.FullTrip,
		valTime time.Time) (*drkey.Lvl2Key, error)
	TelescopeUpstream(ctx context.Context, ases []addr.IA) (*colibri.ReservationLooks, error)
}

type BootstrapProvider struct {
	//TODO(JordiSubira): Make fields private once integration with
	// COLIBRI is possible. At the moment, this allows init in the
	// integration test.
	LocalIA        addr.IA
	LocalHost      addr.HostAddr
	Builder        SetReqBuilder
	Mgr            ExtendedReservationManager
	CryptoProvider ClientCryptoProvider
	Lvl2DB         drkey.Lvl2DB
}

func NewBootstrapProvider(localHost addr.HostAddr, topo topology.Topology,
	db drkey.Lvl2DB, mgr ExtendedReservationManager,
	cryptoProvider ClientCryptoProvider) *BootstrapProvider {
	return &BootstrapProvider{
		LocalIA:   topo.IA(),
		LocalHost: localHost,
		Builder: &builder{
			localIA: topo.IA(),
			topo:    topo,
			Store:   mgr.Store(),
		},
		Mgr:            mgr,
		Lvl2DB:         db,
		CryptoProvider: cryptoProvider,
	}
}

func (b *BootstrapProvider) TelescopeUpstream(ctx context.Context, ases []addr.IA) (*colibri.ReservationLooks, error) {
	segRInfo, err := b.telescopeFromLocal(ctx, ases, len(ases)-1)
	if err != nil {
		return nil, serrors.WrapStr("telescoping from local", err)
	}
	return segRInfo.Reservation, nil
}

type segRInfo struct {
	Reservation *colibri.ReservationLooks
	SegSetupR   *segment.SetupReq
}

// Base case:
// - Check if a key for AS = ases[1] exist at rest. If not the key is fetched using the
//   NR (neighbor reservation from ases[0] tot ases[1]).
// - A segR from ases[0] up to ases[1] is returned.
// Induction step:
// - There exist a valid segR from ases[0] up to ases[index-1] (previousSeg)
// - Check if a key for AS = ases[index] exist at rest. If not the key is fetched using the
//   previousSegID + NR (neighbor reservation from ases[index-1] tot ases[index]).
// - the previousSeg is freed and a segR from ases[0] up to ases[index] is returned
func (b *BootstrapProvider) telescopeFromLocal(ctx context.Context, ases []addr.IA, index int) (segRInfo, error) {
	logger := log.FromCtx(ctx)
	var previousSegInfo segRInfo
	var err error
	if index > 1 {
		previousSegInfo, err = b.telescopeFromLocal(ctx, ases, index-1)
		if err != nil {
			return segRInfo{}, err
		}
	}
	as := ases[index]
	lvl2Meta := drkey.Lvl2Meta{
		KeyType: drkey.AS2Host,
		SrcIA:   as,
		DstIA:   b.LocalIA,
		DstHost: b.LocalHost,
	}

	// XXX(JordiSubira): Lookup request should be conveyed over EER to achieve
	// stronger guarantees. Similar to what is done in the Bootstrapper.SendDRKeyReq
	nr, err := b.lookupNR(ctx, ases[index-1], ases[index])
	if err != nil {
		return segRInfo{}, err
	}

	var stichingSeg []*colibri.ReservationLooks
	// Base case
	if index == 1 {
		stichingSeg = []*colibri.ReservationLooks{nr}
	} else {
		stichingSeg = []*colibri.ReservationLooks{previousSegInfo.Reservation, nr}
	}

	now := time.Now()

	_, err = b.Lvl2DB.GetLvl2Key(ctx, lvl2Meta, util.TimeToSecs(now))
	if err != nil && err != sql.ErrNoRows {
		return segRInfo{}, err
	}
	if err == sql.ErrNoRows {
		logger.Debug("Lvl2 key not in persistance, send request over trip",
			"dstIA", lvl2Meta.SrcIA)
		_, err = b.SendDRKeyReq(ctx, stichingSeg, now)
		if err != nil {
			return segRInfo{}, err
		}
	}

	if index == 1 {
		return segRInfo{
			Reservation: nr,
		}, nil
	}

	setupReq, err := b.Builder.BuildSetReq(ctx, stichingSeg, ases[index])
	if err != nil {
		return segRInfo{}, serrors.WrapStr("building SegR setup request", err)
	}
	// Clean previous segment
	if index > 2 {
		if err := b.tearDownSeg(ctx, &previousSegInfo.SegSetupR.Request); err != nil {
			return segRInfo{}, err
		}
	}

	reservation, err := b.sendSetupUpSegR(ctx, setupReq)
	if err != nil {
		return segRInfo{}, serrors.WrapStr("sending setup request", err)
	}
	return segRInfo{
		Reservation: reservation,
		SegSetupR:   setupReq,
	}, nil
}

func (b *BootstrapProvider) SendDRKeyReq(ctx context.Context, trip colibri.FullTrip, valTime time.Time) (*drkey.Lvl2Key, error) {

	pubKey, privKey, err := b.CryptoProvider.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	req := DRKeyReq{
		EphPubkey:   pubKey,
		ValTime:     valTime,
		SegmentRsvs: trip.Segments(),
	}
	signedReq, err := b.CryptoProvider.Sign(ctx, req)
	if err != nil {
		return nil, err
	}
	signedResp, err := b.Mgr.DRKey(ctx, signedReq)
	if err != nil {
		return nil, err
	}
	key, err := b.CryptoProvider.VerifyDecrypt(ctx, privKey, trip.DstIA(), signedResp)
	if err != nil {
		return nil, err
	}
	err = b.Lvl2DB.InsertLvl2Key(ctx, *key)
	if err != nil {
		return nil, err
	}
	return key, err
}

func (b *BootstrapProvider) sendSetupUpSegR(ctx context.Context, segSetupReq *segment.SetupReq) (*colibri.ReservationLooks, error) {

	// This initSegmentReservation travels over COLIBRI
	if err := b.Mgr.SetupRequest(ctx, segSetupReq); err != nil {
		return nil, serrors.WrapStr("init segment reservation over EER", err)
	}

	// At this point we have establish a segR from local AS to dst

	// XXX(JordiSubira): Lookup request should be conveyed over EER to achieve
	// stronger guarantees. Similar to what is done in the Bootstrapper.SendDRKeyReq
	segReservations, err := b.Mgr.Store().ListReservations(ctx, segSetupReq.Path.DstIA(), lib_res.UpPath)
	if err != nil {
		return nil, serrors.WrapStr("listing reservations to dst", err)
	}
	if len(segReservations) == 0 {
		return nil, serrors.New("No reservations after bootstrap segR", "dst", segSetupReq.Path.DstIA())
	}

	// TODO(JordiSubira): Check if segReservation.Id == segSetupReq.Request.MsgId.ID
	return segReservations[0], nil
}

func (b *BootstrapProvider) tearDownSeg(ctx context.Context, req *reservation.Request) error {

	_, err := b.Mgr.Store().TearDownSegmentReservation(ctx, req)
	return err
}

func (b *BootstrapProvider) listStitchableSegments(ctx context.Context, dst addr.IA) (*colibri.StitchableSegments, error) {
	return b.Mgr.Store().ListStitchableSegments(ctx, dst)
}
func (b *BootstrapProvider) lookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (*colibri.ReservationLooks, error) {
	return b.Mgr.LookupNR(ctx, transferIA, dst)
}
