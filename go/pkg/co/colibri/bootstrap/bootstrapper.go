package bootstrap

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstore"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

var ErrMissingKey = serrors.New("Problem getting key for intermediate AS")

type ExtendedReservationManager interface {
	reservationstore.Manager
	Lvl1(context.Context, *cryptopb.SignedMessage) (*cryptopb.SignedMessage, error)
	LookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (*colibri.ReservationLooks, error)

	GetLvl1(context.Context, drkey.Lvl1Meta, time.Time) (*drkey.Lvl1Key, error)
	StoreLvl1(context.Context, *drkey.Lvl1Key) error
}

type Lvl1Req struct {
	EphPubkey   []byte           // PubKey for deriving/encrypting Lvl1Key message in KEM/DEM
	Certificate x509.Certificate // include certificate to check signature
	ValTime     time.Time

	SegmentRsvs []lib_res.ID
}

type Lvl1Resp struct {
	EphPubkey   []byte           // PubKey for deriving/encrypting Lvl1Key message in KEM/DEM
	Certificate x509.Certificate // include certificate to check signature
	Chiper      []byte
}

// type AsymServerProvider interface {
// 	GenerateKeyPair() ([]byte, []byte, error)
// 	Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
// 		associatedData ...[]byte) (Lvl1Req, error)
// 	EncryptAndSign(lvl1Key drkey.Lvl1Key) (*cryptopb.SignedMessage, error)
// }

type AsymClientProvider interface {
	GenerateKeyPair() ([]byte, []byte, error)
	Sign(ctx context.Context, request Lvl1Req) (*cryptopb.SignedMessage, error)
	VerifyAndDecrypt(ctx context.Context, targetIA addr.IA, privKey []byte,
		signedMsg *cryptopb.SignedMessage, associatedData ...[]byte) (*drkey.Lvl1Key, error)
}

type Bootstrapper interface {
	TelescopeFromLocal(ctx context.Context, ases []seg.ASEntry, index int) (*colibri.ReservationLooks, error)
	BootstrapKey(ctx context.Context, segments []*colibri.ReservationLooks) (drkey.Lvl1Key, error)
}

type BootstrapProvider struct {
	localIA addr.IA
	builder SetReqBuilder

	Mgr ExtendedReservationManager
	// The DRKeyProvider will be used to grab keys for intermediate keys
	// with whatever strategy the caller has decided. It is possible to reuse
	// the BootstrapProvider for resolving intermediate keys, provided that
	// the trip is always trimmed.
	DRKeyProvider  DRKeyProvider
	CryptoProvider AsymClientProvider
}

func NewBootstrapProvider(topo topology.Topology, mgr ExtendedReservationManager,
	drkeyProvider DRKeyProvider, cryptoProvider AsymClientProvider) *BootstrapProvider {
	return &BootstrapProvider{
		localIA: topo.IA(),
		builder: &builder{
			localIA: topo.IA(),
			topo:    topo,
			Mgr:     mgr,
		},

		Mgr:            mgr,
		DRKeyProvider:  drkeyProvider,
		CryptoProvider: cryptoProvider,
	}
}

// BootstrapKey checks that Lvl1Keys for intermediate ASes are not missing.
// This is a safety check. If we call BootstrapLvl1Key without having intermediate keys in cache
// the call will fail and so will the bootstrap request. The Lvl1Req payload must be authenticated
// at every hop B_i expect for the last one with K^Col_{A->B_i}.
func (b *BootstrapProvider) BootstrapKey(ctx context.Context, trip colibri.FullTrip, valTime time.Time) (*drkey.Lvl1Key, error) {
	if len(trip) < 1 {
		return nil, serrors.New("Invalid provided trip to bootstrap a lvl1key")
	}
	path := trip[len(trip)-1].Path
	lastStep := path[len(path)-1]

	for _, segR := range trip {
		for _, step := range segR.Path {
			if step != lastStep {
				lvl1Meta := drkey.Lvl1Meta{
					SrcIA: step.IA,
					DstIA: b.localIA,
				}
				_, err := b.DRKeyProvider.GetLvl1(ctx, lvl1Meta, valTime)
				if err != nil {
					return nil, serrors.Wrap(ErrMissingKey, err)
				}
			}
		}
	}
	// At this point we can create a Lvl1Req since we have all intermediate keys to authenticate
	// the payload.
	return b.sendLvl1Req(ctx, trip, valTime)
}

func (b *BootstrapProvider) TelescopeFromLocal(ctx context.Context, ases []seg.ASEntry) (*colibri.ReservationLooks, error) {
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
func (b *BootstrapProvider) telescopeFromLocal(ctx context.Context, ases []seg.ASEntry, index int) (segRInfo, error) {
	var previousSegInfo segRInfo
	var err error
	if index > 1 {
		previousSegInfo, err = b.telescopeFromLocal(ctx, ases, index-1)
		if err != nil {
			return segRInfo{}, err
		}
	}
	as := ases[index]
	lvl1Meta := drkey.Lvl1Meta{
		SrcIA: as.Local,
		DstIA: b.localIA,
	}

	nr, err := b.lookupNR(ctx, ases[index-1].Local, ases[index].Local)
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
	key, err := b.Mgr.GetLvl1(ctx, lvl1Meta, now)
	if err != nil {
		return segRInfo{}, err
	}
	if key == nil {
		_, err = b.bootstrapLvl1Key(ctx, b.localIA, stichingSeg, now)
		if err != nil {
			return segRInfo{}, err
		}
	}

	if index == 1 {
		return segRInfo{
			Reservation: nr,
		}, nil
	}

	setupReq, err := b.builder.BuildSetReq(ctx, stichingSeg, ases[index].Local)
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
	return segRInfo{
		Reservation: reservation,
		SegSetupR:   setupReq,
	}, nil
}

// bootstrapLvl1Key must receive as an input a valid sequence of segments throughout which it
// will convey the Colibri Lvl1Request. If succesful, the key will be stored in persistance,
// to be used in the future.
func (b *BootstrapProvider) bootstrapLvl1Key(ctx context.Context, dst addr.IA,
	segments []*colibri.ReservationLooks, valTime time.Time) (*drkey.Lvl1Key, error) {
	lvl1Key, err := b.sendLvl1Req(ctx, segments, valTime)
	if err != nil {
		return nil, err
	}
	err = b.Mgr.StoreLvl1(ctx, lvl1Key)
	if err != nil {
		return nil, err
	}
	return lvl1Key, nil
}

func (b *BootstrapProvider) sendLvl1Req(ctx context.Context, trip colibri.FullTrip, valTime time.Time) (*drkey.Lvl1Key, error) {

	pubKey, privKey, err := b.CryptoProvider.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	lvl1req := Lvl1Req{
		EphPubkey:   pubKey,
		ValTime:     valTime,
		SegmentRsvs: trip.Segments(),
	}
	signedLvl1Req, err := b.CryptoProvider.Sign(ctx, lvl1req)
	signedLvl1Resp, err := b.Mgr.Lvl1(ctx, signedLvl1Req)
	return b.CryptoProvider.VerifyAndDecrypt(ctx, trip.DstIA(), privKey, signedLvl1Resp)
}

func (b *BootstrapProvider) sendSetupUpSegR(ctx context.Context, segSetupReq *segment.SetupReq) (*colibri.ReservationLooks, error) {

	// This initSegmentReservation travels over COLIBRI
	if err := b.Mgr.SetupRequest(ctx, segSetupReq); err != nil {
		return nil, serrors.WrapStr("init segment reservation over EER", err)
	}

	// At this point we have establish a segR from local AS to dst
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
