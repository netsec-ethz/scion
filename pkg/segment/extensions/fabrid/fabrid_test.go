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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
)

func TestSupportedIndicesSortedKeys(t *testing.T) {
	connectionPairs := []ConnectionPair{
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 25,
			},
			Egress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 25,
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 31,
			},
			Egress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 28,
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 11,
			},
			Egress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 25,
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:   IPv4Range,
				Prefix: 24,
				IP:     "192.168.2.100",
			},
			Egress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 2,
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:   IPv4Range,
				Prefix: 24,
				IP:     "192.168.2.101",
			},
			Egress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 2,
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 2,
			},
			Egress: ConnectionPoint{
				Type:   IPv4Range,
				Prefix: 24,
				IP:     "192.168.2.101",
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 2,
			},
			Egress: ConnectionPoint{
				Type:   IPv4Range,
				Prefix: 24,
				IP:     "192.168.2.101",
			},
		},
		{
			Ingress: ConnectionPoint{
				Type:        Interface,
				InterfaceId: 3,
			},
			Egress: ConnectionPoint{
				Type:   IPv4Range,
				Prefix: 24,
				IP:     "192.168.2.101",
			},
		},
	}
	tests := map[string]struct {
		Input    SupportedIndicesMap
		Expected []ConnectionPair
	}{
		"base": {
			Input: SupportedIndicesMap{
				connectionPairs[0]: []uint8{0},
				connectionPairs[1]: []uint8{1},
				connectionPairs[2]: []uint8{2},
				connectionPairs[3]: []uint8{3},
				connectionPairs[4]: []uint8{4},
				connectionPairs[5]: []uint8{5},
				connectionPairs[6]: []uint8{5}, // 6 is a duplicate of 5.
				connectionPairs[7]: []uint8{7},
			},
		},
		"reversed": {
			Input: SupportedIndicesMap{
				connectionPairs[7]: []uint8{7},
				connectionPairs[6]: []uint8{5}, // 6 is a duplicate of 5.
				connectionPairs[5]: []uint8{5},
				connectionPairs[4]: []uint8{4},
				connectionPairs[3]: []uint8{3},
				connectionPairs[2]: []uint8{2},
				connectionPairs[1]: []uint8{1},
				connectionPairs[0]: []uint8{0},
			},
		},
		"random": {
			Input: SupportedIndicesMap{
				connectionPairs[4]: []uint8{4},
				connectionPairs[2]: []uint8{2},
				connectionPairs[6]: []uint8{5}, // 6 is a duplicate of 5.
				connectionPairs[1]: []uint8{1},
				connectionPairs[3]: []uint8{3},
				connectionPairs[7]: []uint8{7},
				connectionPairs[0]: []uint8{0},
				connectionPairs[5]: []uint8{5},
			},
		},
		"random-duplicates": {
			Input: SupportedIndicesMap{
				connectionPairs[2]: []uint8{2},
				connectionPairs[4]: []uint8{4},
				connectionPairs[2]: []uint8{2},
				connectionPairs[3]: []uint8{3},
				connectionPairs[6]: []uint8{5}, // 6 is a duplicate of 5.
				connectionPairs[1]: []uint8{1},
				connectionPairs[3]: []uint8{3},
				connectionPairs[7]: []uint8{7},
				connectionPairs[3]: []uint8{3},
				connectionPairs[0]: []uint8{0},
				connectionPairs[5]: []uint8{5},
			},
		},
		"random-duplicates-copy": {
			Input: SupportedIndicesMap{
				connectionPairs[7]: []uint8{7},
				connectionPairs[4]: []uint8{4},
				connectionPairs[2]: []uint8{2},
				connectionPairs[3]: []uint8{3},
				connectionPairs[6]: []uint8{5}, // 6 is a duplicate of 5.
				connectionPairs[0]: []uint8{0},
				connectionPairs[2]: []uint8{2},
				connectionPairs[1]: []uint8{1},
				connectionPairs[5]: []uint8{5},
				connectionPairs[3]: []uint8{3},
				connectionPairs[5]: []uint8{5},
				connectionPairs[3]: []uint8{3},
			},
		},
	}
	input := tests["base"].Input
	baseSorted := input.SortedKeys()
	baseOrder := make([]uint8, 0, len(tests["base"].Input))
	for _, connectionPair := range baseSorted {
		fmt.Println(tests["base"].Input[connectionPair][0])
		baseOrder = append(baseOrder, tests["base"].Input[connectionPair][0])
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			order := make([]uint8, 0, len(tc.Input))
			for _, connectionPair := range tc.Input.SortedKeys() {
				order = append(order, tc.Input[connectionPair][0])
			}
			assert.Equal(t, baseOrder, order)
		})
	}
}

func TestConnectionPointFromString(t *testing.T) {
	type TestCase struct {
		IP     string
		Prefix uint32
		Type   ConnectionPointType
	}
	tests := map[string]struct {
		Eq1 TestCase
		Eq2 TestCase
	}{
		"ipv4": {TestCase{
			IP:     "192.168.2.101",
			Prefix: 24,
			Type:   IPv4Range,
		}, TestCase{
			IP:     "192.168.2.100",
			Prefix: 24,
			Type:   IPv4Range,
		}},
		"ipv4-2": {TestCase{
			IP:     "192.168.2.101",
			Prefix: 24,
			Type:   IPv4Range,
		}, TestCase{
			IP:     "192.168.2.100",
			Prefix: 24,
			Type:   IPv4Range,
		}},
		"ipv4-3": {TestCase{
			IP:     "192.168.3.155",
			Prefix: 16,
			Type:   IPv4Range,
		}, TestCase{
			IP:     "192.168.2.100",
			Prefix: 16,
			Type:   IPv4Range,
		}},
		"ipv4-4": {TestCase{
			IP:     "192.168.3.101",
			Prefix: 2,
			Type:   IPv4Range,
		}, TestCase{
			IP:     "192.168.3.102",
			Prefix: 2,
			Type:   IPv4Range,
		}},
		"ipv6-1": {TestCase{
			IP:     "2001:0db8:85a3::8a2e:0370:7334",
			Prefix: 1,
			Type:   IPv6Range,
		}, TestCase{
			IP:     "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			Prefix: 1,
			Type:   IPv6Range,
		}},
		"ipv6-2": {TestCase{
			IP:     "2001:0db8:85a3::8a2e:0370:7338",
			Prefix: 24,
			Type:   IPv6Range,
		}, TestCase{
			IP:     "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			Prefix: 24,
			Type:   IPv6Range,
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, IPConnectionPointFromString(tc.Eq1.IP, tc.Eq1.Prefix, tc.Eq1.Type).IP,
				IPConnectionPointFromString(tc.Eq2.IP, tc.Eq2.Prefix, tc.Eq2.Type).IP)
		})
	}
}

func TestDetachedToFromPB(t *testing.T) {
	tests := map[string]struct {
		Expected *Detached
		Input    *experimental.FABRIDDetachedExtension
	}{
		"nil": {},
		"index-identifiers only": {
			Expected: &Detached{
				SupportedIndicesMap: SupportedIndicesMap{},
				IndexIdentiferMap: IndexIdentifierMap{
					2: &PolicyIdentifier{
						IsLocal:    false,
						Identifier: 22,
					},
					8: &PolicyIdentifier{
						IsLocal:    true,
						Identifier: 1,
					},
					15: &PolicyIdentifier{
						IsLocal:    false,
						Identifier: 50,
					},
				},
			},
			Input: &experimental.FABRIDDetachedExtension{Maps: &experimental.
				FABRIDDetachableMaps{
				IndexIdentifierMap: map[uint32]*experimental.FABRIDPolicyIdentifier{
					2: {
						PolicyIsLocal:    false,
						PolicyIdentifier: 22,
					},
					8: {
						PolicyIsLocal:    true,
						PolicyIdentifier: 1,
					},
					15: {
						PolicyIsLocal:    false,
						PolicyIdentifier: 50,
					},
				},
			}},
		},
		"index-identifiers and supported indices": {
			Expected: &Detached{
				SupportedIndicesMap: SupportedIndicesMap{
					ConnectionPair{
						Ingress: ConnectionPoint{
							Type:   IPv4Range,
							IP:     "192.168.2.0",
							Prefix: 24,
						},
						Egress: ConnectionPoint{
							Type:        Interface,
							InterfaceId: 5,
						},
					}: []uint8{2, 8, 15},
					ConnectionPair{
						Ingress: ConnectionPoint{
							Type:        Interface,
							InterfaceId: 5,
						},
						Egress: ConnectionPoint{
							Type:        Interface,
							InterfaceId: 6,
						},
					}: []uint8{2, 15},
					ConnectionPair{
						Ingress: ConnectionPoint{
							Type:        Interface,
							InterfaceId: 9,
						},
						Egress: ConnectionPoint{
							Type:   IPv4Range,
							IP:     "192.168.55.0",
							Prefix: 24,
						},
					}: []uint8{2, 15},
				},
				IndexIdentiferMap: IndexIdentifierMap{
					2: &PolicyIdentifier{
						IsLocal:    false,
						Identifier: 22,
					},
					8: &PolicyIdentifier{
						IsLocal:    true,
						Identifier: 1,
					},
					15: &PolicyIdentifier{
						IsLocal:    false,
						Identifier: 50,
					},
				},
			},
			Input: &experimental.FABRIDDetachedExtension{Maps: &experimental.
				FABRIDDetachableMaps{
				SupportedIndicesMap: []*experimental.FABRIDIndexMapEntry{
					{
						IePair: &experimental.FABRIDIngressEgressPair{
							Ingress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
								Interface: 9,
							},
							Egress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV4_RANGE,
								IpAddress: []byte{192, 168, 55, 0},
								IpPrefix:  24,
							},
						},
						SupportedPolicyIndices: []uint32{2, 15},
					}, {
						IePair: &experimental.FABRIDIngressEgressPair{
							Ingress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
								Interface: 5,
							},
							Egress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
								Interface: 6,
							},
						},
						SupportedPolicyIndices: []uint32{2, 15},
					}, {
						IePair: &experimental.FABRIDIngressEgressPair{
							Ingress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV4_RANGE,
								IpAddress: []byte{192, 168, 2, 0},
								IpPrefix:  24,
							},
							Egress: &experimental.FABRIDConnectionPoint{
								Type: experimental.
									FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
								Interface: 5,
							},
						},
						SupportedPolicyIndices: []uint32{2, 8, 15},
					},
				},
				IndexIdentifierMap: map[uint32]*experimental.FABRIDPolicyIdentifier{
					2: {
						PolicyIsLocal:    false,
						PolicyIdentifier: 22,
					},
					8: {
						PolicyIsLocal:    true,
						PolicyIdentifier: 1,
					},
					15: {
						PolicyIsLocal:    false,
						PolicyIdentifier: 50,
					},
				},
			}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.Expected, DetachedFromPB(tc.Input))
			assert.Equal(t, tc.Expected, DetachedFromPB(DetachedToPB(tc.Expected)))
		})
	}

}
func TestHash(t *testing.T) {
	eq1 := &Detached{
		SupportedIndicesMap: SupportedIndicesMap{
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.2.0",
					Prefix: 24,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
			}: []uint8{2, 8, 15},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 6,
				},
			}: []uint8{2, 15},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 9,
				},
				Egress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.55.0",
					Prefix: 24,
				},
			}: []uint8{2, 15},
		},
		IndexIdentiferMap: IndexIdentifierMap{
			2: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 22,
			},
			8: &PolicyIdentifier{
				IsLocal:    true,
				Identifier: 1,
			},
			15: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 50,
			},
		},
	}
	eq2 := &Detached{
		SupportedIndicesMap: SupportedIndicesMap{
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 9,
				},
				Egress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.55.0",
					Prefix: 24,
				},
			}: []uint8{15, 2},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 6,
				},
			}: []uint8{15, 2},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.2.0",
					Prefix: 24,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
			}: []uint8{15, 8, 2},
		},
		IndexIdentiferMap: IndexIdentifierMap{
			15: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 50,
			},
			8: &PolicyIdentifier{
				IsLocal:    true,
				Identifier: 1,
			},
			2: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 22,
			},
		},
	}
	eq3 := &Detached{
		SupportedIndicesMap: SupportedIndicesMap{
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 9,
				},
				Egress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.55.0",
					Prefix: 24,
				},
			}: []uint8{2, 15},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 6,
				},
			}: []uint8{2, 15},
			ConnectionPair{
				Ingress: ConnectionPoint{
					Type:   IPv4Range,
					IP:     "192.168.2.0",
					Prefix: 24,
				},
				Egress: ConnectionPoint{
					Type:        Interface,
					InterfaceId: 5,
				},
			}: []uint8{2, 8, 1}, // Difference to eq2.
		},
		IndexIdentiferMap: IndexIdentifierMap{
			15: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 50,
			},
			8: &PolicyIdentifier{
				IsLocal:    true,
				Identifier: 1,
			},
			2: &PolicyIdentifier{
				IsLocal:    false,
				Identifier: 22,
			},
		},
	}
	assert.Equal(t, eq1.Hash(), eq2.Hash())
	assert.NotEqual(t, eq1.Hash(), eq3.Hash())
}
