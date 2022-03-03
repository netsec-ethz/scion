package bootstrap

import (
	"context"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/crypto"
	pb "github.com/scionproto/scion/go/pkg/proto/colibri"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

var nonce = [24]byte{}

// FakeExtendedMgr contains a mock-up implementation for the
// ExtendedReservationManager interface.

// This class can be remove  we the COLIBRI service provides
// this interface and tests have been adapted.
type FakeExtendedMgr struct {
	localIA   addr.IA
	localHost addr.HostAddr
	fakeStore *FakeStore
}

func NewFakeExtendedMgr(localIA addr.IA, localHost addr.HostAddr,
	store *FakeStore) *FakeExtendedMgr {
	return &FakeExtendedMgr{
		localIA:   localIA,
		localHost: localHost,
		fakeStore: store,
	}
}

// DRKey handles the protobuf request and returns a protobuf response.
// The request is not authenticated.
func (m *FakeExtendedMgr) DRKey(_ context.Context,
	req *pb.DRKeyRequest) (*pb.DRKeyResponse, error) {
	body, err := m.getResponseBody(req)
	if err != nil {
		return nil, err
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}

	rawHdrAndBody, err := proto.Marshal(&cryptopb.HeaderAndBodyInternal{
		Body: rawBody,
	})
	if err != nil {
		return nil, serrors.WrapStr("packing signature input", err)
	}
	signedMsg := &cryptopb.SignedMessage{
		HeaderAndBody: rawHdrAndBody,
	}

	return &pb.DRKeyResponse{
		SignedResponse: signedMsg,
	}, nil
}

func (m *FakeExtendedMgr) getResponseBody(req *pb.DRKeyRequest) (*pb.DRKeyResponseBody, error) {
	lastSegID := *translate.ID(req.Segments[len(req.Segments)-1])
	// srcIA should be extracted from certificate but we are
	// disregarding whether one is actually embedded in the request.
	srcIA := addr.IA{
		I: m.localIA.I, //same ISD as issuer
		A: lastSegID.ASID,
	}

	body, err := signed.ExtractUnverifiedBody(req.SignedRequest)
	if err != nil {
		return nil, serrors.WrapStr("extracting message", err)
	}

	// extract EphPubKey and cipher and decrypt
	var reqBody pb.DRKeyRequestBody
	err = proto.Unmarshal(body, &reqBody)
	if err != nil {
		return nil, serrors.WrapStr("parsing response body", err)
	}

	remoteKey := reqBody.EphPubkey
	pubKey, privKey, err := crypto.GenKeyPair()
	if err != nil {
		return nil, err
	}

	key := fakeKey(srcIA, m.localIA, m.localHost)
	pbResp, err := keyToLvl2Resp(key)
	if err != nil {
		return nil, err
	}
	msg, err := proto.Marshal(pbResp)
	if err != nil {
		return nil, err
	}
	cipher, err := crypto.Encrypt(msg, nonce[:], remoteKey, privKey)
	if err != nil {
		return nil, err
	}

	return &pb.DRKeyResponseBody{
		EphPubkey: pubKey,
		Nonce:     nonce[:],
		Cipher:    cipher,
	}, nil
}

func keyToLvl2Resp(drkey drkey.Lvl2Key) (*pb.ASHostResponse, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from key", err)
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from key", err)
	}

	return &pb.ASHostResponse{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Key:        []byte(drkey.Key),
	}, nil
}

func fakeKey(srcIA, dstIA addr.IA, dstHost addr.HostAddr) drkey.Lvl2Key {
	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  drkey.AS2Host,
			Protocol: "colibri",
			Epoch:    drkey.NewEpoch(0, 100),
			SrcIA:    srcIA,
			DstIA:    dstIA,
			DstHost:  dstHost,
		},
		Key: drkey.DRKey([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}
}

// LookupNR returns the NR for the given transferIA and the dst IA.
func (m *FakeExtendedMgr) LookupNR(ctx context.Context,
	transferIA addr.IA, dst addr.IA) (*colibri.ReservationLooks, error) {
	return &colibri.ReservationLooks{
		Id: lib_res.ID{
			ASID:   transferIA.A,
			Suffix: []byte{255, 255, 255, 255},
		},
		SrcIA: transferIA,
		DstIA: dst,
		Path: []base.PathStep{
			{
				IA: transferIA,
			},
			{
				IA: dst,
			},
		},
	}, nil
}

// SetupRequest simulates sending a segment SetupReq that will be conveyed upstream
// protected by the SegR+NR. The created SegR gets inserted in persistence
func (m *FakeExtendedMgr) SetupRequest(ctx context.Context, req *segment.SetupReq) error {
	srcIA := req.Path.SrcIA()
	dstIA := req.Path.DstIA()
	segR := &colibri.ReservationLooks{
		Id:    req.ID,
		SrcIA: srcIA,
		DstIA: dstIA,
		Path: []base.PathStep{
			{
				IA: srcIA,
			},
			// omit paths in the middle
			{
				IA: dstIA,
			},
		},
	}
	m.fakeStore.InsertUpReservation(dstIA, segR)
	return nil
}

func (m *FakeExtendedMgr) Store() reservationstorage.Store {
	return m.fakeStore
}

// FakeStore keeps an in-memory storage for COLIBRI reservations.
type FakeStore struct {
	upSegRStorage map[addr.IA]*colibri.ReservationLooks
	stichableSeg  map[addr.IA]*colibri.StitchableSegments
}

func NewFakeStore(stichableSeg map[addr.IA]*colibri.StitchableSegments) *FakeStore {
	return &FakeStore{
		upSegRStorage: map[addr.IA]*colibri.ReservationLooks{},
		stichableSeg:  stichableSeg,
	}
}

func (m *FakeStore) InsertUpReservation(key addr.IA, segR *colibri.ReservationLooks) {
	m.upSegRStorage[key] = segR
}

func (m *FakeStore) ListReservations(ctx context.Context, dstIA addr.IA, _ reservation.PathType) (
	[]*colibri.ReservationLooks, error) {
	seg, ok := m.upSegRStorage[dstIA]
	if !ok {
		return nil, serrors.New("no available segment")
	}
	return []*colibri.ReservationLooks{seg}, nil
}

func (m *FakeStore) TearDownSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {
	delete(m.upSegRStorage, req.Path.DstIA())
	return nil, nil
}

func (m *FakeStore) ListStitchableSegments(ctx context.Context,
	dst addr.IA) (*colibri.StitchableSegments, error) {
	stichable, ok := m.stichableSeg[dst]
	if ok {
		ups := make([]*colibri.ReservationLooks, 0, len(m.upSegRStorage))
		for _, rsv := range m.upSegRStorage {
			ups = append(ups, rsv)
		}
		stichable.Up = ups
	}
	return stichable, nil
}

func (m *FakeStore) AdmitSegmentReservation(ctx context.Context, req *segment.SetupReq) (
	segment.SegmentSetupResponse, error) {
	panic("not implemented")
}
func (m *FakeStore) ConfirmSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {
	panic("not implemented")
}
func (m *FakeStore) ActivateSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {
	panic("not implemented")
}
func (m *FakeStore) CleanupSegmentReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {
	panic("not implemented")
}
func (m *FakeStore) AdmitE2EReservation(ctx context.Context, req *e2e.SetupReq) (
	e2e.SetupResponse, error) {
	panic("not implemented")
}
func (m *FakeStore) CleanupE2EReservation(ctx context.Context, req *base.Request) (
	base.Response, error) {
	panic("not implemented")
}
func (m *FakeStore) DeleteExpiredIndices(ctx context.Context,
	now time.Time) (int, time.Time, error) {
	panic("not implemented")
}

func (m *FakeStore) GetReservationsAtSource(ctx context.Context,
	dstIA addr.IA) ([]*segment.Reservation, error) {
	panic("not implemented")
}

func (m *FakeStore) InitSegmentReservation(ctx context.Context,
	req *segment.SetupReq) error {
	panic("not implemented")
}

func (m *FakeStore) AddAdmissionEntry(ctx context.Context,
	entry *colibri.AdmissionEntry) (time.Time, error) {
	panic("not implemented")
}

func (m *FakeStore) DeleteExpiredAdmissionEntries(ctx context.Context,
	now time.Time) (int, time.Time, error) {
	panic("not implemented")
}

func (m *FakeStore) ReportSegmentReservationsInDB(ctx context.Context) (
	[]*segment.Reservation, error) {
	panic("not implemented")
}
func (m *FakeStore) ReportE2EReservationsInDB(ctx context.Context) (
	[]*e2e.Reservation, error) {
	panic("not implemented")
}
