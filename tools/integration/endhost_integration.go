// Copyright 2024 ETH Zurich
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

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology"
)

type dockerizedEndhostIntegration struct {
	*binaryIntegration
}

func NewBinaryEndhostIntegration(name string, cmd string, clientArgs,
	serverArgs []string) Integration {
	logDir := filepath.Join(LogDir(), name)
	err := os.Mkdir(logDir, os.ModePerm)
	if err != nil && !os.IsExist(err) {
		log.Error("Failed to create log folder for testrun", "dir", name, "err", err)
		return nil
	}
	bi := &binaryIntegration{
		name:       name,
		cmd:        cmd,
		clientArgs: clientArgs,
		serverArgs: serverArgs,
		logDir:     logDir,
	}
	return dockerizeEndhost(bi)
}

func dockerizeEndhost(bi *binaryIntegration) Integration {
	if *Docker {
		return &dockerizedEndhostIntegration{
			binaryIntegration: bi,
		}
	}
	return bi
}

// StartServer starts a server and blocks until the ReadySignal is received on Stdout.
func (di *dockerizedEndhostIntegration) StartServer(ctx context.Context, dst *snet.UDPAddr) (Waiter,
	error) {
	bi := *di.binaryIntegration
	bi.serverArgs = append(dockerArgs,
		append([]string{EndhostID(dst), bi.cmd}, bi.serverArgs...)...)
	bi.cmd = dockerCmd
	log.Debug(fmt.Sprintf("Starting server for %s in a docker container",
		addr.FormatIA(dst.IA, addr.WithFileSeparator())),
	)
	return bi.StartServer(ctx, dst)
}

func (di *dockerizedEndhostIntegration) StartClient(ctx context.Context,
	src, dst *snet.UDPAddr) (*BinaryWaiter, error) {
	bi := *di.binaryIntegration
	bi.clientArgs = append(dockerArgs,
		append([]string{EndhostID(src), bi.cmd}, bi.clientArgs...)...)
	bi.cmd = dockerCmd
	log.Debug(fmt.Sprintf("Starting client for %s in a docker container",
		addr.FormatIA(src.IA, addr.WithFileSeparator())),
	)
	return bi.StartClient(ctx, src, dst)
}

func EndhostID(a *snet.UDPAddr) string {
	ia := addr.FormatIA(a.IA, addr.WithFileSeparator())
	envID, ok := os.LookupEnv(fmt.Sprintf("endhost_%s", strings.Replace(ia, "-", "_", -1)))
	if !ok {
		return fmt.Sprintf("endhost_%s", ia)
	}
	return envID
}

// SDAddr reads the endhost (dockerized) or scion daemon (normal) host Addr from the topology
// for the specified IA. If the address cannot be found, the CS address is returned.
var SDAddr HostAddr = func(ia addr.IA) *snet.UDPAddr {
	if a := loadAddr(ia); a != nil {
		return a
	}
	var name string
	if *Docker {
		name = "endhost_"
	} else {
		name = "sd"
	}
	if raw, err := os.ReadFile(GenFile("networks.conf")); err == nil {
		pattern := fmt.Sprintf("%s%s = (.*)", name, addr.FormatIA(ia, addr.WithFileSeparator()))
		matches := regexp.MustCompile(pattern).FindSubmatch(raw)
		if len(matches) == 2 {
			return &snet.UDPAddr{IA: ia, Host: &net.UDPAddr{IP: net.ParseIP(string(matches[1]))}}
		}
	}
	path := GenFile(
		filepath.Join(
			addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
			"topology.json",
		),
	)
	topo, err := topology.RWTopologyFromJSONFile(path)
	if err != nil {
		log.Error("Error loading topology", "err", err)
		os.Exit(1)
	}
	cs := topo.CS["cs"+addr.FormatIA(ia, addr.WithFileSeparator())+"-1"]
	return &snet.UDPAddr{IA: ia, Host: cs.SCIONAddress}
}
