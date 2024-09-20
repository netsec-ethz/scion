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

package fabrid

import (
	"encoding/binary"
	"hash/fnv"
	"sort"

	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

type PolicyIPRange struct {
	MPLSLabel uint32
	IP        []byte
	Prefix    uint32
}

type MplsMaps struct {
	IPPoliciesMap        map[uint32][]PolicyIPRange
	InterfacePoliciesMap map[uint64]uint32
	CurrentHash          []byte
}

func NewMplsMaps() *MplsMaps {
	return &MplsMaps{
		IPPoliciesMap:        make(map[uint32][]PolicyIPRange),
		InterfacePoliciesMap: make(map[uint64]uint32),
		CurrentHash:          []byte{},
	}
}

func (m *MplsMaps) AddConnectionPoint(ie fabrid.ConnectionPair, mplsLabel uint32, policyIdx uint8) {
	if mplsLabel == 0 {
		return
	}
	if ie.Egress.Type == fabrid.IPv4Range || ie.Egress.
		Type == fabrid.IPv6Range { // Egress is IP network:
		key := 1<<31 + uint32(policyIdx)         // Wildcard ingress interface
		if ie.Ingress.Type == fabrid.Interface { // Specified ingress interface
			key = uint32(ie.Ingress.InterfaceId)<<8 + uint32(policyIdx)
		}
		m.IPPoliciesMap[key] = append(m.IPPoliciesMap[key], PolicyIPRange{
			IP:        ie.Egress.IPNetwork().IP,
			Prefix:    ie.Egress.Prefix,
			MPLSLabel: mplsLabel})
	} else {
		egIf := uint64(0)
		if ie.Egress.Type == fabrid.Interface {
			egIf = uint64(ie.Egress.InterfaceId)
		}
		// Wildcard ingress interface:
		key := 1<<63 + egIf<<8 + uint64(policyIdx)
		if ie.Ingress.Type == fabrid.Interface { // Specified ingress interface
			key = uint64(ie.Ingress.InterfaceId)<<24 + egIf<<8 + uint64(policyIdx)
		}
		m.InterfacePoliciesMap[key] = mplsLabel
	}
}

func sortedKeys[K uint32 | uint64, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return keys
}

// This method is to be called after all inserts and removes from the internal map and calculates
// the hash for the MPLS map according to the entries. The order of insertion is not relevant here.
func (m *MplsMaps) UpdateHash() {
	h := fnv.New64()
	for _, polIdx := range sortedKeys(m.IPPoliciesMap) {
		_ = binary.Write(h, binary.BigEndian, polIdx)
		for _, ipRange := range m.IPPoliciesMap[polIdx] {
			_ = binary.Write(h, binary.BigEndian, ipRange.MPLSLabel)
			_, _ = h.Write(ipRange.IP)
			_ = binary.Write(h, binary.BigEndian, ipRange.Prefix)
		}
	}

	for _, polIdx := range sortedKeys(m.InterfacePoliciesMap) {
		_ = binary.Write(h, binary.BigEndian, polIdx)
		_ = binary.Write(h, binary.BigEndian, m.InterfacePoliciesMap[polIdx])
	}
	m.CurrentHash = h.Sum(nil)
}
