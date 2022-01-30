package bootstrap_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/mock_bootstrap"
)

var (
	isd103 = xtest.MustParseIA("1-1:ff00:103")
	isd102 = xtest.MustParseIA("1-1:ff00:102")
	isd101 = xtest.MustParseIA("1-1:ff00:101")
	isd100 = xtest.MustParseIA("1-1:ff00:100")
	isd110 = xtest.MustParseIA("1-1:ff00:110")
	isd111 = xtest.MustParseIA("1-1:ff00:110")
	isd112 = xtest.MustParseIA("1-1:ff00:110")
)

func TestTelescopeFromLocal(t *testing.T) {

	ases := []seg.ASEntry{
		{
			Local: isd103,
		},
		{
			Local: isd102,
		},
		{
			Local: isd101,
		},
		// Core AS
		{
			Local: isd100,
		},
	}
	targetSegID := lib_res.ID{
		ASID:   isd103.A,
		Suffix: []byte{0, 0, 103, 100},
	}

	nrIDs := map[string]*colibri.ReservationLooks{
		"nr-1:ff00:103-1:ff00:102": {
			Id: lib_res.ID{
				ASID:   isd103.A,
				Suffix: []byte{0, 0, 103, 102},
			},
		},
		"nr-1:ff00:102-1:ff00:101": {
			Id: lib_res.ID{
				ASID:   isd103.A,
				Suffix: []byte{0, 0, 102, 101},
			},
		},
		"nr-1:ff00:101-1:ff00:100": {
			Id: lib_res.ID{
				ASID:   isd103.A,
				Suffix: []byte{0, 0, 101, 100},
			},
		},
	}
	segRs := map[string]*colibri.ReservationLooks{}
	lvl1KeyMap := map[addr.IA]*drkey.Lvl1Key{
		isd102: {
			Lvl1Meta: drkey.Lvl1Meta{
				SrcIA: isd102,
				DstIA: isd103,
			},
		},
	}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	provider := mock_bootstrap.NewMockColibriProvider(mctrl)
	provider.EXPECT().LookupNR(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, src addr.IA, dstIA addr.IA) (*colibri.ReservationLooks, error) {
			key := "nr-" + src.A.String() + "-" + dstIA.A.String()
			return nrIDs[key], nil
		})

	//
	provider.EXPECT().BootstrapLvl1Key(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
		func(_ context.Context, trip colibri.FullTrip) (*drkey.Lvl1Key, error) {
			var srcIAid string
			segments := trip.Segments()
			if len(segments) > 1 {
				require.Equal(t, segments[0].Suffix[3], segments[1].Suffix[2])
				srcIAid = strconv.Itoa(int(segments[1].Suffix[3]))
			} else {
				srcIAid = strconv.Itoa(int(segments[0].Suffix[3]))
			}
			return &drkey.Lvl1Key{
				Lvl1Meta: drkey.Lvl1Meta{
					SrcIA: xtest.MustParseIA("1-1:ff00:" + srcIAid),
					DstIA: isd103,
				},
			}, nil
		})
	provider.EXPECT().StoreLvl1(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
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
	provider.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, lvl1meta drkey.Lvl1Meta, _ uint32) (*drkey.Lvl1Key, error) {
			srcIA := lvl1meta.SrcIA
			key, ok := lvl1KeyMap[srcIA]
			if ok {
				return key, nil
			}
			return nil, nil
		})

	provider.EXPECT().TearDownSeg(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, seg *colibri.ReservationLooks) error {
			srcAS := seg.Id.ASID
			dstAS := "1:ff00:" + strconv.Itoa(int(seg.Id.Suffix[3]))
			key := "seg-" + srcAS.String() + "-" + dstAS
			require.Contains(t, segRs, key)
			return nil
		})

	provider.EXPECT().SetupUpSegR(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, trip colibri.FullTrip, dst addr.IA) (*colibri.ReservationLooks, error) {
			segs := trip.Segments()
			require.Len(t, segs, 2)
			require.Equal(t, segs[0].Suffix[3], segs[1].Suffix[2])

			srcAS := segs[0].ASID
			dstAS := "1:ff00:" + strconv.Itoa(int(segs[1].Suffix[3]))
			key := "seg-" + srcAS.String() + "-" + dstAS
			segR := &colibri.ReservationLooks{
				Id: lib_res.ID{
					ASID:   srcAS,
					Suffix: []byte{0, 0, segs[0].Suffix[2], segs[1].Suffix[3]},
				},
			}
			segRs[key] = segR
			return segR, nil
		})

	b := bootstrap.BootstrapProvider{
		ColProvider: provider,
	}

	seg, err := b.TelescopeFromLocal(context.Background(), ases)
	require.NoError(t, err)
	require.Equal(t, seg.Id, targetSegID)

}

func TestBootstrapKey(t *testing.T) {
	cases := []struct {
		name          string
		trip          colibri.FullTrip
		provider      func(ctrl *gomock.Controller) bootstrap.ColibriProvider //func(context.Context, drkey.Lvl1Meta, uint32) (*drkey.Lvl1Key, error))
		expectedError error
	}{
		{
			name: "available_keys",
			trip: colibri.FullTrip{
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd103,
						},
						{
							IA: isd102,
						},
						{
							IA: isd101,
						},
						{
							IA: isd100,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd100,
						},
						{
							IA: isd110,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd111,
						},
						{
							IA: isd112,
						},
					},
				},
			},
			provider: func(ctrl *gomock.Controller) bootstrap.ColibriProvider {
				p := mock_bootstrap.NewMockColibriProvider(ctrl)
				p.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
					&drkey.Lvl1Key{}, nil)

				p.EXPECT().BootstrapLvl1Key(gomock.Any(), gomock.Any()).Return(
					&drkey.Lvl1Key{}, nil)
				return p
			},
			expectedError: nil,
		},
		{
			name: "error_int_key",
			trip: colibri.FullTrip{
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd103,
						},
						{
							IA: isd102,
						},
						{
							IA: isd101,
						},
						{
							IA: isd100,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd100,
						},
						{
							IA: isd110,
						},
					},
				},
				&colibri.ReservationLooks{
					Path: []reservation.PathStep{
						{
							IA: isd111,
						},
						{
							IA: isd112,
						},
					},
				},
			},
			provider: func(ctrl *gomock.Controller) bootstrap.ColibriProvider {
				p := mock_bootstrap.NewMockColibriProvider(ctrl)
				p.EXPECT().GetLvl1(gomock.Any(), drkey.Lvl1Meta{SrcIA: isd110}, gomock.Any()).Return(
					nil, &bootstrap.BootstrapError{
						MissingIA: isd110,
					},
				)
				p.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
					&drkey.Lvl1Key{}, nil)

				return p
			},
			expectedError: &bootstrap.BootstrapError{
				MissingIA: isd110,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			b := bootstrap.BootstrapProvider{
				ColProvider: c.provider(mctrl),
			}

			_, err := b.BootstrapKey(context.Background(), c.trip)
			if c.expectedError != nil {
				assert.Equal(t, c.expectedError, err)
			} else {
				require.NoError(t, err)
			}

		})
	}

}
