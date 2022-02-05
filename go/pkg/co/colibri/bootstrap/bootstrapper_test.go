package bootstrap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage/mock_reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	rsv "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/mock_bootstrap"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

var (
	ia103 = xtest.MustParseIA("1-1:ff00:103")
	ia102 = xtest.MustParseIA("1-1:ff00:102")
	ia101 = xtest.MustParseIA("1-1:ff00:101")
	ia100 = xtest.MustParseIA("1-1:ff00:100")
	ia110 = xtest.MustParseIA("1-1:ff00:110")
	ia111 = xtest.MustParseIA("1-1:ff00:111")
	ia112 = xtest.MustParseIA("1-1:ff00:112")
)

func TestTelescopeFromLocal(t *testing.T) {

	ases := []seg.ASEntry{
		{
			Local: ia103,
		},
		{
			Local: ia102,
		},
		{
			Local: ia101,
		},
		// Core AS
		{
			Local: ia100,
		},
	}
	targetSeg := &colibri.ReservationLooks{
		SrcIA: ia103,
		DstIA: ia100,
	}

	nrIDs := map[string]*colibri.ReservationLooks{
		"nr-1:ff00:103-1:ff00:102": {
			Id: lib_res.ID{
				ASID:   ia103.A,
				Suffix: []byte{0, 0, 103, 102},
			},
			SrcIA: ia103,
			DstIA: ia102,
			Path: []reservation.PathStep{
				{
					IA: ia103,
				},
				// omit paths in the middle
				{
					IA: ia102,
				},
			},
		},
		"nr-1:ff00:102-1:ff00:101": {
			Id: lib_res.ID{
				ASID:   ia103.A,
				Suffix: []byte{0, 0, 102, 101},
			},
			SrcIA: ia102,
			DstIA: ia101,
			Path: []reservation.PathStep{
				{
					IA: ia102,
				},
				// omit paths in the middle
				{
					IA: ia101,
				},
			},
		},
		"nr-1:ff00:101-1:ff00:100": {
			Id: lib_res.ID{
				ASID:   ia103.A,
				Suffix: []byte{0, 0, 101, 100},
			},
			SrcIA: ia101,
			DstIA: ia100,
			Path: []reservation.PathStep{
				{
					IA: ia101,
				},
				// omit paths in the middle
				{
					IA: ia100,
				},
			},
		},
	}
	segRs := map[string]*colibri.ReservationLooks{}
	lvl1KeyMap := map[addr.IA]*drkey.Lvl1Key{
		ia102: {
			Lvl1Meta: drkey.Lvl1Meta{
				SrcIA: ia102,
				DstIA: ia103,
			},
		},
	}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	mgr := mock_bootstrap.NewMockExtendedReservationManager(mctrl)
	storeMgr := mock_reservationstorage.NewMockStore(mctrl)

	mgr.EXPECT().Store().AnyTimes().Return(storeMgr)
	mgr.EXPECT().SetupRequest(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, req *segment.SetupReq) error {
			srcIA := req.Path.SrcIA()
			dstIA := req.Path.DstIA()
			key := "seg-" + srcIA.String() + "-" + dstIA.String()
			segR := &colibri.ReservationLooks{
				Id:    req.ID,
				SrcIA: srcIA,
				DstIA: dstIA,
				Path: []reservation.PathStep{
					{
						IA: srcIA,
					},
					// omit paths in the middle
					{
						IA: dstIA,
					},
				},
			}
			segRs[key] = segR
			return nil
		})
	storeMgr.EXPECT().TearDownSegmentReservation(gomock.Any(), gomock.Any()).Return(nil, nil)
	storeMgr.EXPECT().ListReservations(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, dstIA addr.IA, _ rsv.PathType) ([]*colibri.ReservationLooks, error) {
			key := "seg-" + ia103.String() + "-" + dstIA.String()
			segR, ok := segRs[key]
			require.True(t, ok)
			return []*colibri.ReservationLooks{segR}, nil
		})

	builder := mock_bootstrap.NewMockSetReqBuilder(mctrl)
	builder.EXPECT().BuildSetReq(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, trip colibri.FullTrip, dst addr.IA) (*segment.SetupReq, error) {
			transparentPath := reservation.TransparentPath{
				Steps: []reservation.PathStep{
					{
						IA: trip.SrcIA(),
					},
					// omit paths in the middle
					{
						IA: trip.DstIA(),
					},
				},
			}
			return &segment.SetupReq{
				Request: reservation.Request{
					Path: &transparentPath,
				},
			}, nil
		})

	cryptoProvider := mock_bootstrap.NewMockAsymClientProvider(mctrl)

	mgr.EXPECT().LookupNR(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, src addr.IA, dstIA addr.IA) (*colibri.ReservationLooks, error) {
			key := "nr-" + src.A.String() + "-" + dstIA.A.String()
			return nrIDs[key], nil
		})

	cryptoProvider.EXPECT().GenerateKeyPair().Times(2).Return(nil, nil, nil)
	cryptoProvider.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(2).Return(nil, nil)

	mgr.EXPECT().Lvl1(gomock.Any(), gomock.Any()).Times(2).Return(nil, nil)

	cryptoProvider.EXPECT().VerifyAndDecrypt(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
		func(_ context.Context, targetIA addr.IA, _ []byte,
			_ *cryptopb.SignedMessage, _ ...[]byte) (*drkey.Lvl1Key, error) {

			return &drkey.Lvl1Key{
				Lvl1Meta: drkey.Lvl1Meta{
					SrcIA: targetIA,
					DstIA: ia103,
				},
			}, nil
		})

	mgr.EXPECT().StoreLvl1(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, lvl1Key *drkey.Lvl1Key) error {
			if lvl1Key != nil {
				srcIA := lvl1Key.SrcIA
				_, ok := lvl1KeyMap[srcIA]
				require.False(t, ok)
				lvl1KeyMap[srcIA] = lvl1Key
				return nil
			}
			return fmt.Errorf("invalid lvl1Key")
		})
	mgr.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, lvl1meta drkey.Lvl1Meta, _ time.Time) (*drkey.Lvl1Key, error) {
			srcIA := lvl1meta.SrcIA
			key, ok := lvl1KeyMap[srcIA]
			if ok {
				return key, nil
			}
			return nil, nil
		})

	b := bootstrap.NewTestBootstrapProvider(ia103, builder, mgr, nil, cryptoProvider)

	seg, err := b.TelescopeFromLocal(context.Background(), ases)
	require.NoError(t, err)
	require.Equal(t, targetSeg.SrcIA, seg.SrcIA)
	require.Equal(t, targetSeg.DstIA, seg.DstIA)

}

func TestBootstrapKey(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name           string
		trip           colibri.FullTrip
		valTime        time.Time
		mgr            func(ctrl *gomock.Controller) bootstrap.ExtendedReservationManager
		cryptoProvider func(ctrl *gomock.Controller) bootstrap.AsymClientProvider
		drkeyProvider  func(ctrl *gomock.Controller) bootstrap.DRKeyProvider
		errAssertion   assert.ErrorAssertionFunc
	}{
		{
			name: "available_keys",
			trip: colibri.FullTrip{
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia103,
						},
						{
							IA: ia102,
						},
						{
							IA: ia101,
						},
						{
							IA: ia100,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia100,
						},
						{
							IA: ia110,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia111,
						},
						{
							IA: ia112,
						},
					},
				},
			},
			valTime: now,
			cryptoProvider: func(ctrl *gomock.Controller) bootstrap.AsymClientProvider {
				c := mock_bootstrap.NewMockAsymClientProvider(ctrl)
				c.EXPECT().Sign(gomock.Any(), gomock.Any()).Return(nil, nil)
				c.EXPECT().VerifyAndDecrypt(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(&drkey.Lvl1Key{}, nil)
				return c
			},
			mgr: func(ctrl *gomock.Controller) bootstrap.ExtendedReservationManager {
				p := mock_bootstrap.NewMockExtendedReservationManager(ctrl)

				p.EXPECT().Lvl1(gomock.Any(), gomock.Any()).Return(
					nil, nil)
				return p
			},
			drkeyProvider: func(ctrl *gomock.Controller) bootstrap.DRKeyProvider {
				p := mock_bootstrap.NewMockDRKeyProvider(ctrl)
				p.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
					&drkey.Lvl1Key{}, nil)
				return p
			},
			errAssertion: assert.NoError,
		},
		{
			name: "error_int_key",
			trip: colibri.FullTrip{
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia103,
						},
						{
							IA: ia102,
						},
						{
							IA: ia101,
						},
						{
							IA: ia100,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia100,
						},
						{
							IA: ia110,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: ia111,
						},
						{
							IA: ia112,
						},
					},
				},
			},
			valTime: now,
			mgr: func(ctrl *gomock.Controller) bootstrap.ExtendedReservationManager {
				return nil
			},
			cryptoProvider: func(ctrl *gomock.Controller) bootstrap.AsymClientProvider {
				return nil
			},
			drkeyProvider: func(ctrl *gomock.Controller) bootstrap.DRKeyProvider {
				p := mock_bootstrap.NewMockDRKeyProvider(ctrl)
				p.EXPECT().GetLvl1(gomock.Any(), drkey.Lvl1Meta{SrcIA: ia110}, gomock.Any()).Return(
					nil, serrors.New("No key via best-effort. Abort."),
				)
				p.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
					&drkey.Lvl1Key{}, nil)

				return p
			},
			errAssertion: assert.Error,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			b := bootstrap.BootstrapProvider{
				Mgr:            c.mgr(mctrl),
				CryptoProvider: c.cryptoProvider(mctrl),
				DRKeyProvider:  c.drkeyProvider(mctrl),
			}

			_, err := b.BootstrapKey(context.Background(), c.trip, c.valTime)
			c.errAssertion(t, err)

		})
	}

}
