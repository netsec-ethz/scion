// Copyright 2020 Anapaya Systems
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

package main

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	coli_conf "github.com/scionproto/scion/go/co/reservation/conf"
	admission "github.com/scionproto/scion/go/co/reservation/segment/admission/stateless"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstore"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/coliquic"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	colgrpc "github.com/scionproto/scion/go/pkg/co/colibri/grpc"
	"github.com/scionproto/scion/go/pkg/colibri/config"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
	"github.com/scionproto/scion/go/pkg/storage"
)

func main() {
	var cfg config.Config
	application := launcher.Application{
		TOMLConfig: &cfg,
		ShortName:  "SCION COLIBRI Service",
		Main: func(ctx context.Context) error {
			return realMain(ctx, &cfg)
		},
	}
	application.Run()
}

func realMain(ctx context.Context, cfg *config.Config) error {
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      cfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.ColibriValidator{ID: cfg.General.ID},
		// Metrics: , // TODO(juagargi) add observability to colibri
	})
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

	cfgObjs, err := setup(ctx, cfg, topo)
	if err != nil {
		return err
	}

	var cleanup app.Cleanup
	err = setupColibri(ctx, g, &cleanup, cfg, cfgObjs, topo)
	if err != nil {
		return err
	}

	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})
	return g.Wait()
}

// cfgObjs contains the objects needed for the configuration of colibri.
type cfgObjs struct {
	masterKey keyconf.Master
	stack     *coliquic.ServerStack
	tcpDialer *libgrpc.TCPDialer
}

func setup(ctx context.Context, cfg *config.Config, topo *topology.Loader) (*cfgObjs, error) {
	cfgObjs, err := setupNetwork(ctx, cfg, topo)
	if err != nil {
		return cfgObjs, serrors.WrapStr("setting network config", err)
	}

	cfgObjs.masterKey, err = keyconf.LoadMaster(filepath.Join(cfg.General.ConfigDir, "keys"))
	if err != nil {
		return nil, serrors.WrapStr("error getting master secret", err)
	}

	return cfgObjs, nil
}

func setupNetwork(ctx context.Context, cfg *config.Config, topo *topology.Loader) (
	*cfgObjs, error) {

	serverAddr := &snet.UDPAddr{
		IA:   topo.IA(),
		Host: topo.ColibriServiceAddress(cfg.General.ID),
	}

	stack, err := coliquic.NewServerStack(ctx, serverAddr, cfg.Daemon.Address)
	if err != nil {
		return nil, serrors.WrapStr("initializing server stack", err)
	}

	dialerAddr := &net.TCPAddr{
		IP: serverAddr.Host.IP,
	}
	dialer := &libgrpc.TCPDialer{
		LocalAddr: dialerAddr,
		SvcResolver: func(dst addr.HostSVC) []resolver.Address {
			targets := []resolver.Address{}
			switch dst.Base() {
			case addr.SvcCS:
				for _, entry := range topo.ControlServiceAddresses() {
					targets = append(targets, resolver.Address{Addr: entry.String()})
				}
			default:
				panic("Unsupported address type, implementation error?")
			}
			return targets
		},
	}

	return &cfgObjs{
		stack:     stack,
		tcpDialer: dialer,
	}, nil
}

// setupColibri returns the running manager.
func setupColibri(ctx context.Context, g *errgroup.Group, cleanup *app.Cleanup, cfg *config.Config,
	cfgObjs *cfgObjs, topo *topology.Loader) error {

	db, err := storage.NewColibriStorage(cfg.Colibri.DB)
	if err != nil {
		return serrors.WrapStr("error initializing COLIBRI DB", err)
	}
	cleanup.Add(func() error { return db.Close() })

	admitter := &admission.StatelessAdmission{
		Caps:  cfg.Colibri.Capacities,
		Delta: cfg.Colibri.Delta,
	}
	colibriStore, err := reservationstore.NewStore(topo, cfgObjs.stack.ClientPacketConn,
		cfgObjs.tcpDialer, cfgObjs.stack.Router, cfgObjs.stack.Resolver,
		db, admitter, cfgObjs.masterKey.Key0)
	if err != nil {
		return serrors.WrapStr("initializing colibri store", err)
	}

	colibriService := &colgrpc.ColibriService{
		Store: colibriStore,
	}
	colServer := coliquic.NewGrpcServer(libgrpc.UnaryServerInterceptor())
	tcpColServer := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	colpb.RegisterColibriServiceServer(colServer, colibriService)
	colpb.RegisterColibriServiceServer(tcpColServer, colibriService)

	// run inter and intra AS servers
	g.Go(func() error {
		defer log.HandlePanic()
		lis := cfgObjs.stack.QUICListener
		log.Debug("colibri grpc server listening quic", "addr", lis.Addr())
		return colServer.Serve(lis)
	})
	cleanup.Add(func() error { colServer.GracefulStop(); return nil })

	g.Go(func() error {
		defer log.HandlePanic()
		tcpListener := cfgObjs.stack.TCPListener
		log.Debug("colibri grpc server listening tcp", "tcp_addr", tcpListener.Addr())
		return tcpColServer.Serve(tcpListener)
	})
	cleanup.Add(func() error { tcpColServer.GracefulStop(); return nil })

	manager, err := colibriManager(ctx, topo, cfgObjs.stack.Router, colibriStore,
		cfg.Colibri.Reservations)
	if err != nil {
		return serrors.WrapStr("starting colibri manager", err)
	}
	cleanup.Add(func() error { manager.Kill(); return nil })

	return nil
}

func colibriManager(ctx context.Context, topo *topology.Loader, router snet.Router, store reservationstorage.Store,
	initialRsvs *coli_conf.Reservations) (*periodic.Runner, error) {

	if store == nil {
		return nil, nil
	}
	mgr, err := reservationstore.NewColibriManager(ctx, topo.IA(), router, store, initialRsvs)
	if err != nil {
		return nil, serrors.WrapStr("could not start colibri manager", err)
	}
	return periodic.Start(mgr, 100*time.Millisecond, 5*time.Second), nil
}
