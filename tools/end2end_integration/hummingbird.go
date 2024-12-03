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

package main

import (
	"context"
	"crypto/aes"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	hbird "github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	hbirddp "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/tools/integration"
)

func createMockFlyovers(
	perAS map[addr.IA]topoPerAS,
	now time.Time,
) ([]*hbird.Flyover, error) {

	// Per IA, insert a flyover with BW units of bandwidth for each interface pair.
	// Note that BW has to be enough for one AS to send a ping to another.
	const BW = uint16(10)
	flyovers := make([]*hbird.Flyover, 0)
	for ia, c := range perAS {
		var resIDPerIA uint32 // reservation ID unique per IA
		// Load master key for this ia. It is used to create the mock flyover, by deriving here
		// the correct Ak that the border routers will check.
		masterFile := integration.GenFile(filepath.Join(c.ASDirName, "keys"))
		master0, err := keyconf.LoadMaster(masterFile)
		if err != nil {
			return nil, serrors.WrapStr("could not load master secret for IA", err, "ia", ia)
		}

		// Add the "itself" interface ID to the slice.
		ifaces := append(c.Interfaces, 0)
		// Create a flyover for each possible ingress->egress s.t. ingress <> egress
		inToEgressesMap := ifIDSequenceToMap(ifaces)
		for in, egressInterfaces := range inToEgressesMap {
			for _, eg := range egressInterfaces {
				f := hbird.Flyover{
					BaseHop: hbird.BaseHop{
						IA:      ia,
						Ingress: uint16(in),
						Egress:  uint16(eg),
					},
					Bw:        BW,
					StartTime: util.TimeToSecs(now),
					// Duration:  60,         // 1 Minute
					// deleteme: change to 1 minute again
					Duration: 300,        // 1 Hour
					ResID:    resIDPerIA, // unique per ia
				}

				key0 := control.DeriveHbirdSecretValue(master0.Key0)
				prf, _ := aes.NewCipher(key0)
				buffer := make([]byte, 16)
				ak := hbirddp.DeriveAuthKey(prf, f.ResID, f.Bw, f.Ingress, f.Egress,
					f.StartTime, f.Duration, buffer)
				copy(f.Ak[:], ak[0:16])

				// Increment the reservation ID per AS to make it unique (per AS).
				resIDPerIA++

				flyovers = append(flyovers, &f)
			}
		}
	}
	return flyovers, nil
}

func insertFlyoversInAS(
	ctx context.Context,
	ia addr.IA,
	config topoPerAS,
	flyovers []*hbird.Flyover,
) error {

	daemonAddr, err := integration.GetSCIONDAddress(
		integration.GenFile(integration.DaemonAddressesFile), ia)
	if err != nil {
		return serrors.WrapStr("getting the sciond address", err, "ia", ia)
	}
	conn, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("opening daemon connection", err, "ia", ia)
	}

	err = conn.StoreFlyovers(ctx, flyovers)
	if err != nil {
		return serrors.WrapStr("storing flyovers using daemon", err, "ia", ia)
	}

	err = conn.Close()
	if err != nil {
		return serrors.WrapStr("closing daemon connection", err, "ia", ia)
	}

	return nil
}

// ifIDSequenceToMap takes a slice of interfaces and returns a map where each ingress has
// a list to egress interfaces from the slice.
func ifIDSequenceToMap(ifSeq []common.IFIDType) map[common.IFIDType][]common.IFIDType {

	m := make(map[common.IFIDType][]common.IFIDType, len(ifSeq))
	for _, src := range ifSeq {
		for _, dst := range ifSeq {
			if src == dst {
				continue
			}
			m[src] = append(m[src], dst)
		}
	}
	return m
}
