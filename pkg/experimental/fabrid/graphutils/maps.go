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

package graphutils

import (
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/scionproto/scion/pkg/snet"
)

// We go through the list of ASEntries and store for each IA a pointer to the FABRID
// Map found in the ASEntries' extensions.  If there is already a map stored, check the info time,
// and replace with the newer FABRID maps. This results in a map[IA]FabridMapEntry, which can be
// used to find the policies that are available for each of the interface pairs on the path.
type FabridMapEntry struct {
	Map *fabrid_ext.Detached
	Ts  time.Time
	// The Digest of the Fabrid Maps, this can be empty.
	Digest []byte
}

func CollectFabridPolicies(ifaces []snet.PathInterface,
	maps map[addr.IA]FabridMapEntry) []snet.FabridInfo {

	switch {
	case len(ifaces)%2 != 0:
		return []snet.FabridInfo{}
	case len(ifaces) == 0:
		return []snet.FabridInfo{}
	default:
		fabridInfo := make([]snet.FabridInfo, len(ifaces)/2+1)
		fabridInfo[0] = *GetFabridInfoForIntfs(ifaces[0].IA, 0, uint16(ifaces[0].ID), maps, false)
		for i := 1; i < len(ifaces)-1; i += 2 {
			fabridInfo[(i+1)/2] = *GetFabridInfoForIntfs(ifaces[i].IA, uint16(ifaces[i].ID),
				uint16(ifaces[i+1].ID), maps, false)
		}
		fabridInfo[len(ifaces)/2] = *GetFabridInfoForIntfs(ifaces[len(ifaces)-1].IA,
			uint16(ifaces[len(ifaces)-1].ID), 0, maps, true)
		return fabridInfo
	}
}

func GetFabridInfoForIntfs(ia addr.IA, ig, eg uint16, maps map[addr.IA]FabridMapEntry,
	allowIpPolicies bool) *snet.FabridInfo {
	policies := make([]*fabrid.Policy, 0)
	fabridMap, exist := maps[ia]
	if !exist {
		return &snet.FabridInfo{
			Enabled:  false,
			Policies: policies,
			Digest:   []byte{},
			Detached: false,
		}
	} else if fabridMap.Map == nil {
		return &snet.FabridInfo{
			Enabled:  true,
			Policies: policies,
			Digest:   fabridMap.Digest,
			Detached: len(fabridMap.Digest) > 0,
		}
	}
	for k, v := range fabridMap.Map.SupportedIndicesMap {
		if !k.Matches(ig, eg, allowIpPolicies) {
			continue
		}
		for _, policy := range v {
			val, ok := fabridMap.Map.IndexIdentiferMap[policy]
			if !ok {
				continue
			}
			policies = append(policies, &fabrid.Policy{
				IsLocal:    val.IsLocal,
				Identifier: val.Identifier,
				Index:      fabrid.PolicyID(policy),
			})

		}
	}

	return &snet.FabridInfo{
		Enabled:  true,
		Policies: policies,
		Digest:   fabridMap.Digest,
		Detached: false,
	}
}
