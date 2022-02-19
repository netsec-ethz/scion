package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap"
)

var (
	ia1_A   = xtest.MustParseIA("1-ff00:0:112") // Source
	ia1_B_1 = xtest.MustParseIA("1-ff00:0:121") // Up
	ia1_B_2 = xtest.MustParseIA("1-ff00:0:111") // Up
	ia1_C_1 = xtest.MustParseIA("1-ff00:0:120") // Core
	ia1_C_2 = xtest.MustParseIA("1-ff00:0:110") // Core
	ia1_D   = xtest.MustParseIA("1-ff00:0:130") // Core
	ia1_E   = xtest.MustParseIA("1-ff00:0:131")
	ia1_F   = xtest.MustParseIA("1-ff00:0:132")

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
		DstIA: ia1_C_2,
		Path: []reservation.PathStep{
			{
				IA: ia1_A,
			},
			{
				IA: ia1_B_2,
			},
			{
				IA: ia1_C_2,
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

func main() {
	os.Exit(realMain())
}

type pather struct {
	localIA addr.IA
	daemon  daemon.Connector
}

func (p *pather) Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return p.daemon.Paths(ctx, dst, p.localIA, daemon.PathReqFlags{})
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()

	var remote snet.UDPAddr
	var timeout = util.DurWrap{Duration: 3 * time.Second}
	addFlags(&remote, &timeout)
	integration.Setup()

	closeTracer, err := integration.InitTracer("bootstrap-" + integration.Mode)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()

	stichableReservation := initReservations()
	healtyIAs := initHealthyIAs()

	localIA := integration.Local.IA
	localHost := addr.HostFromIP(integration.Local.Host.IP)
	fakeStore := bootstrap.NewFakeStore(stichableReservation)
	db := bootstrap.NewFakeDB(localIA, localHost, healtyIAs)

	bs := bootstrap.DRKeyBootstrapper{
		LocalIA:   localIA,
		LocalHost: localHost,
		Provider: &bootstrap.FakeProvider{
			DB: db,
		},
		ColStore: fakeStore,
		Bootstrapper: &bootstrap.BootstrapProvider{
			LocalIA:   localIA,
			LocalHost: localHost,
			Builder:   bootstrap.FakeBuilder{},
			Mgr:       bootstrap.NewFakeExtendedMgr(localIA, localHost, fakeStore),
			CryptoProvider: bootstrap.FakeCryptoProvider{
				LocalIA:   integration.Local.IA,
				LocalHost: localHost,
			},
			Lvl2DB: db,
		},
		SegProvider: bootstrap.NewSegProvider(&pather{
			localIA: integration.Local.IA,
			daemon:  integration.SDConn(),
		}),
	}
	ctx := log.CtxWith(context.Background(), log.Root())
	metaF := drkey.Lvl2Meta{SrcIA: ia1_F, DstIA: ia1_A}
	key, err := bs.GetKey(ctx, metaF, time.Now())
	if err != nil {
		integration.LogFatal("Not able to bootrstrap key", "err", err)
	}
	log.Root().Debug("SUCCESS", "key", key)
	return 0
}

func addFlags(remote *snet.UDPAddr, timeout *util.DurWrap) {
	flag.Var(remote, "ddos-ia", "simulation ia under dos")
	flag.Var(timeout, "timeout", `The timeout for each attempt (default "3s")`)
}

func initReservations() map[addr.IA]*colibri.StitchableSegments {
	return map[addr.IA]*colibri.StitchableSegments{
		ia1_F: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_F,
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
			Down:  []*colibri.ReservationLooks{segRD_E_F},
		},
		ia1_D: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_D,
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
		},
		ia1_E: &colibri.StitchableSegments{
			SrcIA: ia1_A,
			DstIA: ia1_E,
			Core:  []*colibri.ReservationLooks{segRC1_C2_D},
			Down:  []*colibri.ReservationLooks{segRD_E},
		},
	}
}

func initHealthyIAs() []addr.IA {
	return []addr.IA{}
}

// loadTRCs is a helper function to load the two latest TRCs from files. If any
// file cannot be read, a nil slice is returned and an error.
func loadTRCs() ([]*cppki.TRC, error) {
	return []*cppki.TRC{}, nil
}
