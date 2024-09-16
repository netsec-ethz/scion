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

package snet

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/common"
)

// HopInterface represents a single hop on the path
type HopInterface struct {
	// IgIf represents the ingress interface ID for a hop in the path.
	IgIf common.IFIDType
	// EgIf represents the ingress interface ID for a hop in the path.
	EgIf common.IFIDType
	// IA is the ISD AS identifier of the hop.
	IA addr.IA
	// FabridEnabled indicates whether FABRID is enabled on this hop.
	FabridEnabled bool
	// Policies are the FABRID Policies that are supported by this hop.
	Policies []*fabrid.Policy
}

type FabridInfo struct {
	// Enabled contains a boolean indicating whether the hop supports FABRID.
	Enabled bool
	// Policies Contains the policy identifiers that can be used on this hop
	Policies []*fabrid.Policy
	// Digest contains the FABRID digest for the AS. This is used when the
	// FABRID extension is detached.
	Digest []byte
	// Detached indicates whether the FABRID maps have been detached from the PCB for this hop.
	// This can happen as the PCB is propagated, or when the AS does not add the detachable FABRID
	// extension.
	Detached bool
}

func (pm *PathMetadata) Hops() []HopInterface {
	ifaces := pm.Interfaces
	fabrid := pm.FabridInfo
	switch {
	case len(ifaces)%2 != 0 || (len(fabrid) != len(ifaces)/2+1):
		return []HopInterface{}
	case len(ifaces) == 0 || len(fabrid) == 0:
		return []HopInterface{}
	default:
		hops := make([]HopInterface, 0, len(ifaces)/2+1)
		hops = append(hops, HopInterface{
			IA:            ifaces[0].IA,
			IgIf:          0,
			EgIf:          ifaces[0].ID,
			FabridEnabled: fabrid[0].Enabled,
			Policies:      fabrid[0].Policies})
		for i := 1; i < len(ifaces)-1; i += 2 {
			hops = append(hops, HopInterface{
				IA:            ifaces[i].IA,
				IgIf:          ifaces[i].ID,
				EgIf:          ifaces[i+1].ID,
				FabridEnabled: fabrid[(i+1)/2].Enabled,
				Policies:      fabrid[(i+1)/2].Policies,
			})
		}
		hops = append(hops, HopInterface{
			IA:            ifaces[len(ifaces)-1].IA,
			IgIf:          ifaces[len(ifaces)-1].ID,
			EgIf:          0,
			FabridEnabled: fabrid[len(ifaces)/2].Enabled,
			Policies:      fabrid[len(ifaces)/2].Policies,
		})
		return hops
	}
}
