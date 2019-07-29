// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/cert_srv/internal/drkey"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

var (
	cfg              config.Config
	state            *config.State
	reissRunner      *periodic.Runner
	discRunners      idiscovery.Runners
	corePusher       *periodic.Runner
	drkeyStoreKeeper *periodic.Runner
	drkeyRequester   *periodic.Runner
	msgr             infra.Messenger
	trustDB          trustdb.TrustDB
)

func init() {
	flag.Usage = env.Usage
}

// main initializes the certificate server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.CS, cfg.General.ID)
	defer log.LogPanicAndExit()
	// Setup the state and the messenger
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	tracer, trCloser, err := cfg.Tracing.NewTracer(cfg.General.ID)
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)
	// Start the periodic reissuance task.
	startReissRunner()
	// Start the DRKey periodic tasks
	startDRKeyRunners()
	// Start the periodic fetching from discovery service.
	startDiscovery()
	// Start the messenger.
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	// Cleanup when the CS exits.
	defer stop()
	cfg.Metrics.StartPrometheus()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

// startReissRunner starts a periodic reissuance task. Core starts self-issuer.
// Non-core starts a requester.
func startReissRunner() {
	corePusher = periodic.StartPeriodicTask(
		&reiss.CorePusher{
			LocalIA: itopo.Get().ISD_AS,
			TrustDB: state.TrustDB,
			Msger:   msgr,
		},
		periodic.NewTicker(time.Hour),
		time.Minute,
	)
	corePusher.TriggerRun()
	if !cfg.CS.AutomaticRenewal {
		log.Info("Reissue disabled, not starting reiss task.")
		return
	}
	if itopo.Get().Core {
		log.Info("Starting periodic reiss.Self task")
		reissRunner = periodic.StartPeriodicTask(
			&reiss.Self{
				Msgr:       msgr,
				State:      state,
				IA:         itopo.Get().ISD_AS,
				IssTime:    cfg.CS.IssuerReissueLeadTime.Duration,
				LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
				CorePusher: corePusher,
			},
			periodic.NewTicker(cfg.CS.ReissueRate.Duration),
			cfg.CS.ReissueTimeout.Duration,
		)
		return
	}
	log.Info("Starting periodic reiss.Requester task")
	reissRunner = periodic.StartPeriodicTask(
		&reiss.Requester{
			Msgr:       msgr,
			State:      state,
			IA:         itopo.Get().ISD_AS,
			LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
			CorePusher: corePusher,
		},
		periodic.NewTicker(cfg.CS.ReissueRate.Duration),
		cfg.CS.ReissueTimeout.Duration,
	)
}

func startDRKeyRunners() {
	// TODO drkeytest: if there has been a change in the duration, we probably need to keep
	// the already sent keys (and their duration) as they were already handed to other entities
	storeKeeperPeriod := 2 * cfg.CS.DRKeyDuration.Duration
	// TODO drkeytest: the duration of the requester must depend on the present keys, not on our SV
	requesterPeriod := cfg.CS.DRKeyDuration.Duration / 2
	if storeKeeperPeriod < 2*requesterPeriod {
		// since the keeper removes keys, the requester must see them before removal at least once
		fatal.Fatal(common.NewBasicError("DRKey start failed: the removal of expired keys happens "+
			"too often compared to the request of new level 1 keys", nil,
			"removal period", storeKeeperPeriod, "requester period", requesterPeriod))
	}
	drkeyStoreKeeper = periodic.StartPeriodicTask(
		&drkey.StoreKeeper{
			State: state,
		},
		periodic.NewTicker(storeKeeperPeriod),
		time.Minute,
	)
	// TODO drkeytest: check the timeout value
	drkeyRequester = periodic.StartPeriodicTask(
		&drkey.Requester{
			Msgr:  msgr,
			State: state,
			IA:    itopo.Get().ISD_AS,
		},
		periodic.NewTicker(requesterPeriod),
		time.Minute,
	)
}

func startDiscovery() {
	var err error
	discRunners, err = idiscovery.StartRunners(cfg.Discovery, discovery.Full,
		idiscovery.TopoHandlers{}, nil)
	if err != nil {
		fatal.Fatal(common.NewBasicError("Unable to start dynamic topology fetcher", err))
	}
}

func stopReissRunner() {
	if corePusher != nil {
		corePusher.Kill()
	}
	if reissRunner != nil {
		reissRunner.Stop()
	}
}

func stopDRKeyRunners() {
	if drkeyStoreKeeper != nil {
		drkeyStoreKeeper.Stop()
	}
}

func stop() {
	stopReissRunner()
	stopDRKeyRunners()
	discRunners.Kill()
	msgr.CloseServer()
	trustDB.Close()
}
