package bootstrap_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/lib/addr"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/mock_bootstrap"
	"github.com/stretchr/testify/require"
)

func TestBootstrapKeysRemoteSeg(t *testing.T) {

}

func TestBootstrapIntermediateKeys(t *testing.T) {

}

func TestTelescopeFromLocal(t *testing.T) {
	isd103 := xtest.MustParseIA("1-1:ff00:103")
	isd102 := xtest.MustParseIA("1-1:ff00:102")
	isd101 := xtest.MustParseIA("1-1:ff00:101")
	isd100 := xtest.MustParseIA("1-1:ff00:100")
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

	nrIDs := map[string]lib_res.ID{
		"nr-1:ff00:103-1:ff00:102": {
			ASID:   isd103.A,
			Suffix: []byte{0, 0, 103, 102},
		},
		"nr-1:ff00:102-1:ff00:101": {
			ASID:   isd103.A,
			Suffix: []byte{0, 0, 102, 101},
		},
		"nr-1:ff00:101-1:ff00:100": {
			ASID:   isd103.A,
			Suffix: []byte{0, 0, 101, 100},
		},
	}
	segIDs := map[string]lib_res.ID{}
	lvl1KeyMap := map[addr.IA]drkey.Lvl1Key{
		isd102: {
			Lvl1Meta: drkey.Lvl1Meta{
				ProtoId: drkey.COLIBRI,
				SrcIA:   isd102,
				DstIA:   isd103,
			},
		},
	}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	provider := mock_bootstrap.NewMockColibriProvider(mctrl)
	provider.EXPECT().LookupNR(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, src addr.IA, dstIA addr.IA) (lib_res.ID, error) {
			key := "nr-" + src.A.String() + "-" + dstIA.A.String()
			return nrIDs[key], nil
		})
	provider.EXPECT().BootstrapLvl1Key(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, segments []lib_res.ID) (drkey.Lvl1Key, error) {
			var srcIAid string
			if len(segments) > 1 {
				require.Equal(t, segments[0].Suffix[3], segments[1].Suffix[2])
				srcIAid = strconv.Itoa(int(segments[0].Suffix[3]))
			} else {
				srcIAid = strconv.Itoa(int(segments[1].Suffix[3]))
			}
			return drkey.Lvl1Key{
				Lvl1Meta: drkey.Lvl1Meta{
					ProtoId: drkey.COLIBRI,
					SrcIA:   xtest.MustParseIA("1-1:ff00:" + srcIAid),
					DstIA:   isd103,
				},
			}, nil
		})
	provider.EXPECT().StoreLvl1(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, lvl1Key drkey.Lvl1Key) error {
			srcIA := lvl1Key.SrcIA
			_, ok := lvl1KeyMap[srcIA]
			require.False(t, ok)
			lvl1KeyMap[srcIA] = lvl1Key
			return nil
		})
	provider.EXPECT().GetLvl1(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, lvl1meta drkey.Lvl1Meta, _ uint32) (*drkey.Lvl1Key, error) {
			srcIA := lvl1meta.SrcIA
			key, ok := lvl1KeyMap[srcIA]
			require.True(t, ok)
			return &key, nil
		})

	provider.EXPECT().TearDownSeg(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, seg lib_res.ID) error {
			srcAS := seg.ASID
			dstAS := "1:ff00:" + strconv.Itoa(int(seg.Suffix[3]))
			key := "seg-" + srcAS.String() + "-" + dstAS
			require.Contains(t, segIDs, key)
			return nil
		})

	provider.EXPECT().SetupUpSegR(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, segs []lib_res.ID, dst addr.IA) (lib_res.ID, error) {
			require.Len(t, segs, 2)
			require.Equal(t, segs[0].Suffix[3], segs[1].Suffix[2])

			srcAS := segs[0].ASID
			dstAS := "1:ff00:" + strconv.Itoa(int(segs[1].Suffix[3]))
			key := "seg-" + srcAS.String() + "-" + dstAS
			segID := lib_res.ID{
				ASID:   srcAS,
				Suffix: []byte{0, 0, segs[0].Suffix[2], segs[1].Suffix[3]},
			}
			segIDs[key] = segID
			return segID, nil
		})

	b := bootstrap.TestBootstrapper{
		Bootstrapper: bootstrap.Bootstrapper{
			ColProvider: provider,
		},
	}

	seg, err := b.TelescopeFromLocal(context.Background(), ases, len(ases)-1)
	require.NoError(t, err)
	require.Equal(t, seg, targetSegID)

}
