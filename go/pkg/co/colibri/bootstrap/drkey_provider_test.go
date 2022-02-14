package bootstrap_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservationstorage/mock_reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/mock_bootstrap"
	"github.com/stretchr/testify/assert"
)

var (
	ia1_A   = xtest.MustParseIA("1-1:ff00:103") // Source
	ia1_B_1 = xtest.MustParseIA("1-1:ff00:102") // Up
	ia1_B_2 = xtest.MustParseIA("1-1:ff00:104") // Up
	ia1_C_1 = xtest.MustParseIA("1-1:ff00:101") // Core
	ia1_C_2 = xtest.MustParseIA("1-1:ff00:105") // Core
	ia1_D   = xtest.MustParseIA("1-1:ff00:100") // Core
	ia1_E   = xtest.MustParseIA("1-1:ff00:110")
	ia1_F   = xtest.MustParseIA("1-1:ff00:111")

	segRA_C1 = &colibri.ReservationLooks{
		SrcIA: ia1_A,
		DstIA: ia1_C_1,
		Path: []reservation.PathStep{
			{
				IA: ia1_A,
			},
			{
				IA: ia1_B_1,
			},
			{
				IA: ia1_C_1,
			},
		},
	}

	segRA_C2 = &colibri.ReservationLooks{
		SrcIA: ia1_A,
		DstIA: ia1_C_1,
		Path: []reservation.PathStep{
			{
				IA: ia1_A,
			},
			{
				IA: ia1_B_1,
			},
			{
				IA: ia1_C_1,
			},
		},
	}

	segRC1_C2_D = &colibri.ReservationLooks{
		SrcIA: ia1_C_1,
		DstIA: ia1_D,
		Path: []reservation.PathStep{
			{
				IA: ia1_C_1,
			},
			{
				IA: ia1_C_2,
			},
			{
				IA: ia1_D,
			},
		},
	}

	segRD_E = &colibri.ReservationLooks{
		SrcIA: ia1_D,
		DstIA: ia1_E,
		Path: []reservation.PathStep{
			{
				IA: ia1_D,
			},
			{
				IA: ia1_E,
			},
		},
	}

	segRD_E_F = &colibri.ReservationLooks{
		SrcIA: ia1_D,
		DstIA: ia1_F,
		Path: []reservation.PathStep{
			{
				IA: ia1_D,
			},
			{
				IA: ia1_E,
			},
			{
				IA: ia1_F,
			},
		},
	}
)

func TestGetKey(t *testing.T) {
	upSegToF := [][]addr.IA{
		[]addr.IA{
			ia1_A,
			ia1_B_1,
			ia1_C_1,
		},
		[]addr.IA{
			ia1_A,
			ia1_B_2,
			ia1_C_2,
		},
	}
	upSegToC_2 := [][]addr.IA{
		[]addr.IA{
			ia1_A,
			ia1_B_2,
			ia1_C_2,
		},
	}

	segRs := map[addr.IA]*colibri.StitchableSegments{
		ia1_F: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_F,
			Up:    []*colibri.ReservationLooks{segRA_C1},
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
			Down:  []*colibri.ReservationLooks{segRD_E_F},
		},
		ia1_C_1: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_C_1,
			Up:    []*colibri.ReservationLooks{segRA_C1},
		},
		ia1_C_2: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_C_2,
			Up:    []*colibri.ReservationLooks{segRA_C2},
		},
		ia1_D: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_D,
			Up:    []*colibri.ReservationLooks{segRA_C1},
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
		},
		ia1_E: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_E,
			Up:    []*colibri.ReservationLooks{segRA_C1},
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
			Down:  []*colibri.ReservationLooks{segRD_E},
		},
	}

	metaF := drkey.Lvl2Meta{SrcIA: ia1_F, DstIA: ia1_A}

	// segRLocalStore := map[addr.IA]*colibri.ReservationLooks{}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	storeMgr := mock_reservationstorage.NewMockStore(mctrl)
	bootstrapper := mock_bootstrap.NewMockBootstrapper(mctrl)
	drkeyProvider := mock_bootstrap.NewMockDRKeyProvider(mctrl)
	segProvider := mock_bootstrap.NewMockUpSegProvider(mctrl)

	// M: miss
	// State: A->B1(M)->C1(M)->C2(M)->D(M)->E(M)->F(M)

	drkeyProvider.EXPECT().GetKey(gomock.Any(), metaF,
		gomock.Any()).Return(nil, serrors.New("not able to fetch via best-effort"))
	segProvider.EXPECT().UpSegIAs(gomock.Any(), ia1_F).Return(upSegToF, nil)
	storeMgr.EXPECT().ListReservations(gomock.Any(), ia1_C_1, gomock.Any()).Return(nil, nil) //(ctx context.Context, dst addr.IA) (*colibri.StitchableSegments, error)
	telescopeCallC1 := bootstrapper.EXPECT().TelescopeUpstream(gomock.Any(), upSegToF[0]).Return(nil, nil)
	storeMgr.EXPECT().ListStitchableSegments(gomock.Any(), ia1_F).After(telescopeCallC1).Return(
		segRs[ia1_F], nil)
	// storeMgr.EXPECT().ListStitchableSegments(gomock.Any(), ia1_F).DoAndReturn(
	// 	func(_ context.Context, dst addr.IA) (*colibri.StitchableSegments, error) {
	// 		stichable := segRs[dst]
	// 		// Check UpSeg has been bootstrapped (we only have one up segment in stichables)
	// 		_, ok := segRLocalStore[stichable.Up[0].DstIA]
	// 		require.True(t, ok)
	// 		return stichable, nil
	// 	})

	// State: A->B1->C1->C2(M)->D(M)->E(M)->F(M)

	// Best-effort/Persistance call for B1 and C1
	drkeyProvider.EXPECT().GetKey(gomock.Any(), gomock.Any(),
		gomock.Any()).After(telescopeCallC1).Times(2).Return(nil, nil)

	// Best-effort call for C2
	drkeyProvider.EXPECT().GetKey(gomock.Any(), drkey.Lvl2Meta{SrcIA: ia1_C_2, DstIA: ia1_A},
		gomock.Any()).Return(nil, serrors.New("not able to fetch via best-effort"))
	segProvider.EXPECT().UpSegIAs(gomock.Any(), ia1_C_2).Return(upSegToC_2, nil)
	storeMgr.EXPECT().ListReservations(gomock.Any(), ia1_C_2, gomock.Any()).Return(nil, nil)
	telescopeCallC2 := bootstrapper.EXPECT().TelescopeUpstream(gomock.Any(), upSegToF[1]).Return(nil, nil)
	// Best-effort calls for C2
	drkeyProvider.EXPECT().GetKey(gomock.Any(), gomock.Any(),
		gomock.Any()).After(telescopeCallC2).Times(1).Return(nil, nil)

	// drkeyProvider.EXPECT().GetKey(gomock.Any(), drkey.Lvl2Meta{SrcIA: ia1_C_2, DstIA: ia1_A},
	// 	gomock.Any()).After(telescopeCallC2).Return(nil, nil)

	// State: A->B1->C1->C2->D(M)->E(M)->F(M)
	drkeyProvider.EXPECT().GetKey(gomock.Any(), drkey.Lvl2Meta{SrcIA: ia1_D, DstIA: ia1_A},
		gomock.Any()).Return(nil, serrors.New("not able to fetch via best-effort"))
	segProvider.EXPECT().UpSegIAs(gomock.Any(), ia1_D).Return(upSegToF, nil)
	storeMgr.EXPECT().ListReservations(gomock.Any(), ia1_C_1, gomock.Any()).Return([]*colibri.ReservationLooks{segRA_C1}, nil)
	storeMgr.EXPECT().ListStitchableSegments(gomock.Any(), ia1_D).Return(segRs[ia1_D], nil)
	// Best-effort/persistance for B1->C1->C2
	drkeyProvider.EXPECT().GetKey(gomock.Any(), gomock.Any(),
		gomock.Any()).After(telescopeCallC1).Times(3).Return(nil, nil)
	bootstrapper.EXPECT().SendDRKeyReq(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

	// State: A->B1->C1->C2->D->E(M)->F(M)

	drkeyProvider.EXPECT().GetKey(gomock.Any(), drkey.Lvl2Meta{SrcIA: ia1_E, DstIA: ia1_A},
		gomock.Any()).Return(nil, serrors.New("not able to fetch via best-effort"))
	segProvider.EXPECT().UpSegIAs(gomock.Any(), ia1_E).Return(upSegToF, nil)
	storeMgr.EXPECT().ListReservations(gomock.Any(), ia1_C_1, gomock.Any()).Return([]*colibri.ReservationLooks{segRA_C1}, nil)
	storeMgr.EXPECT().ListStitchableSegments(gomock.Any(), ia1_E).Return(segRs[ia1_E], nil)
	// Best-effort/persistance for B1->C1->C2->D
	drkeyProvider.EXPECT().GetKey(gomock.Any(), gomock.Any(),
		gomock.Any()).After(telescopeCallC1).Times(4).Return(nil, nil)
	bootstrapper.EXPECT().SendDRKeyReq(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

	// State: A->B1->C1->C2->D->E->F(M)
	bootstrapper.EXPECT().SendDRKeyReq(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

	drkeyBootstrapper := &bootstrap.DRKeyBootstrapper{
		LocalIA:      ia103,
		Provider:     drkeyProvider,
		ColStore:     storeMgr,
		Bootstrapper: bootstrapper,
		SegProvider:  segProvider,
	}

	_, err := drkeyBootstrapper.GetKey(context.Background(), metaF, time.Now())
	assert.NoError(t, err)
}
