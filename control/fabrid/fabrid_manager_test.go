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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

func TestLoadInvalidPolicies(t *testing.T) {
	fm := NewFabridManager([]uint16{1, 2}, 5*time.Second)
	err := fm.Load("testdata/mixed")
	require.ErrorContains(t, err, "Unable to parse policy")
}

func TestLoadPolicyWithNonExistingInterfaces(t *testing.T) {
	fm := NewFabridManager([]uint16{1}, 5*time.Second)
	err := fm.Load("testdata/correct")
	require.ErrorContains(t, err, "Interface does not exist")
}

func TestLoadPolicies(t *testing.T) {
	testcases := map[string]struct {
		CP          []config.FABRIDConnectionPoints
		Local       bool
		Description string
		Identifier  uint32
	}{
		"1-global_example.yml": {
			Local:      false,
			Identifier: 1102,
			CP: []config.FABRIDConnectionPoints{{
				Ingress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 2,
				},
				Egress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 1,
				},
				MPLSLabel: 1,
			}},
		},
		"2-global_example.yml": {
			Local:      false,
			Identifier: 1102,
			CP: []config.FABRIDConnectionPoints{{
				Ingress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 2,
				},
				Egress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 1,
				},
				MPLSLabel: 2,
			}},
		},
		"3-local_example.yml": {
			Local:       true,
			Description: "Fabrid Example Policy",
			Identifier:  1103,
			CP: []config.FABRIDConnectionPoints{{
				Ingress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 2,
				},
				Egress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 1,
				},
				MPLSLabel: 5,
			}, {
				Ingress: config.FABRIDConnectionPoint{
					Type: fabrid.Wildcard,
				},
				Egress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 2,
				},
				MPLSLabel: 3,
			}},
		},
		"55-local_example.yml": {
			Local:       true,
			Description: "Fabrid Example Policy 2",
			Identifier:  11055,
			CP: []config.FABRIDConnectionPoints{{
				Ingress: config.FABRIDConnectionPoint{
					Type:      fabrid.Interface,
					Interface: 2,
				},
				Egress: config.FABRIDConnectionPoint{
					Type:      fabrid.IPv4Range,
					IPAddress: "192.168.5.1",
					Prefix:    24,
				},
				MPLSLabel: 55,
			}},
		},
	}

	fm := NewFabridManager([]uint16{1, 2}, 5*time.Second)
	fm.autoIncrIndex = 1
	err := fm.Load("testdata/correct")
	require.NoError(t, err)
	require.Equal(t, 4, len(fm.IndexIdentifierMap))

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {

			if tc.Local {
				require.Equal(t, tc.Description, fm.IdentifierDescriptionMap[tc.Identifier])
			}
			policyIdx := uint8(0)
			for k, v := range fm.IndexIdentifierMap {
				if ((tc.Local && v.IsLocal) || (!tc.Local && !v.
					IsLocal)) && v.Identifier == tc.Identifier {
					policyIdx = k
				}
			}
			require.NotEqual(t, 0, policyIdx)
			for _, cp := range tc.CP {
				ig, err := createConnectionPoint(cp.Ingress)
				require.NoError(t, err)
				eg, err := createConnectionPoint(cp.Egress)
				require.NoError(t, err)
				ie := fabrid.ConnectionPair{
					Ingress: ig,
					Egress:  eg,
				}
				fmt.Println(ie)
				fmt.Println(fm.SupportedIndicesMap)
				require.Contains(t, fm.SupportedIndicesMap[ie], policyIdx)
			}
		})
	}

}

func TestAddPolicy(t *testing.T) {
	cp1 := config.FABRIDConnectionPoints{
		Ingress: config.FABRIDConnectionPoint{
			Type: fabrid.Wildcard,
		},
		Egress: config.FABRIDConnectionPoint{
			Type:      fabrid.IPv4Range,
			IPAddress: "192.168.1.1",
			Prefix:    24,
		},
		MPLSLabel: 12,
	}
	cp2 := config.FABRIDConnectionPoints{
		Ingress: config.FABRIDConnectionPoint{
			Type:      fabrid.Interface,
			Interface: 3,
		},
		Egress: config.FABRIDConnectionPoint{
			Type:      fabrid.Interface,
			Interface: 5,
		},
		MPLSLabel: 13,
	}
	cp3 := config.FABRIDConnectionPoints{
		Ingress: config.FABRIDConnectionPoint{
			Type: fabrid.Wildcard,
		},
		Egress: config.FABRIDConnectionPoint{
			Type:      fabrid.Interface,
			Interface: 7,
		},
		MPLSLabel: 14,
	}

	cp4 := config.FABRIDConnectionPoints{
		Ingress: config.FABRIDConnectionPoint{
			Type: fabrid.Wildcard,
		},
		Egress: config.FABRIDConnectionPoint{
			Type: fabrid.Wildcard,
		},
		MPLSLabel: 15,
	}
	cp5 := config.FABRIDConnectionPoints{
		Ingress: config.FABRIDConnectionPoint{
			Type:      fabrid.Interface,
			Interface: 5,
		},
		Egress: config.FABRIDConnectionPoint{
			Type:      fabrid.IPv4Range,
			IPAddress: "192.168.1.1",
			Prefix:    24,
		},
		MPLSLabel: 16,
	}
	testCases := map[string]struct {
		Policy config.FABRIDPolicy
		Local  bool
	}{
		"Global Policy": {
			Policy: config.FABRIDPolicy{
				IsLocalPolicy:    false,
				GlobalIdentifier: 1,
				SupportedBy: []config.FABRIDConnectionPoints{
					cp1, cp2, cp3, cp4, cp5,
				},
			},
			Local: false,
		},
		"Local Policy": {
			Policy: config.FABRIDPolicy{
				IsLocalPolicy:    true,
				LocalIdentifier:  4,
				LocalDescription: "test policy",
				SupportedBy: []config.FABRIDConnectionPoints{
					cp1, cp2, cp3, cp4, cp5,
				},
			},
			Local: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			fm := NewFabridManager([]uint16{3, 5, 7}, 5*time.Second)
			oldIndex := fm.autoIncrIndex
			err := fm.addPolicy(&tc.Policy)
			newIndex := fm.autoIncrIndex
			require.NoError(t, err)
			//Check if the policy index has updated:
			require.NotEqual(t, oldIndex, newIndex)
			if tc.Local {
				//Check if the policy is in the IdentifierDescriptionMap
				require.Equal(t, fm.IdentifierDescriptionMap[tc.Policy.LocalIdentifier],
					tc.Policy.LocalDescription)
			}
			// Check if the policy has been correctly inserted into the IndexIdentifierMap
			indexIdentifierMapEntry := fm.IndexIdentifierMap[uint8(oldIndex)]
			if tc.Local {
				require.Equal(t, tc.Policy.LocalIdentifier, indexIdentifierMapEntry.Identifier)
				require.True(t, indexIdentifierMapEntry.IsLocal)
			} else {

				require.Equal(t, tc.Policy.GlobalIdentifier, indexIdentifierMapEntry.Identifier)
				require.False(t, indexIdentifierMapEntry.IsLocal)
			}
			//Check if the policy has been inserted correctly into the MPLS Maps:
			cp1_mpls_key := 1<<31 + uint32(oldIndex) // IP
			cp2_mpls_key := uint64(cp2.Ingress.Interface)<<24 + uint64(cp2.Egress.
				Interface)<<8 + uint64(oldIndex)
			cp3_mpls_key := uint64(1)<<63 + uint64(cp3.Egress.Interface)<<8 + uint64(oldIndex)
			cp4_mpls_key := uint64(1)<<63 + uint64(oldIndex)
			cp5_mpls_key := uint32(cp5.Ingress.Interface)<<8 + uint32(oldIndex) // IP

			require.Equal(t, fm.MPLSMap.IPPoliciesMap[cp1_mpls_key][0].MPLSLabel, cp1.MPLSLabel)
			require.Equal(t, fm.MPLSMap.InterfacePoliciesMap[cp2_mpls_key], cp2.MPLSLabel)
			require.Equal(t, fm.MPLSMap.InterfacePoliciesMap[cp3_mpls_key], cp3.MPLSLabel)
			require.Equal(t, fm.MPLSMap.InterfacePoliciesMap[cp4_mpls_key], cp4.MPLSLabel)
			require.Equal(t, fm.MPLSMap.IPPoliciesMap[cp5_mpls_key][0].MPLSLabel, cp5.MPLSLabel)

			//Check if the policy has been added to the SupportedIndicesMap
			for _, cp := range tc.Policy.SupportedBy {
				ig, err := createConnectionPoint(cp.Ingress)
				require.NoError(t, err)
				eg, err := createConnectionPoint(cp.Egress)
				require.NoError(t, err)
				require.Contains(t, fm.SupportedIndicesMap, fabrid.ConnectionPair{
					Ingress: ig, Egress: eg,
				})
				require.Equal(t, uint8(oldIndex), fm.SupportedIndicesMap[fabrid.ConnectionPair{
					Ingress: ig, Egress: eg,
				}][0])
			}
		})
	}

}
func TestCreateConnectionPoint(t *testing.T) {
	testCases := map[string]struct {
		connection        config.FABRIDConnectionPoint
		expectedType      fabrid.ConnectionPointType
		expectedIP        string
		expectedPrefix    uint32
		expectedInterface uint16
		isError           bool
	}{
		"ValidInterfaceType": {
			connection: config.FABRIDConnectionPoint{
				Type:      fabrid.Interface,
				Interface: 15,
			},
			expectedType:      fabrid.Interface,
			expectedInterface: 15,
			isError:           false,
		},
		"ValidIPv4Range": {
			connection: config.FABRIDConnectionPoint{
				Type:      fabrid.IPv4Range,
				IPAddress: "192.168.1.1",
				Prefix:    24,
			},
			expectedType:   fabrid.IPv4Range,
			expectedIP:     "192.168.1.0",
			expectedPrefix: 24,
			isError:        false,
		},
		"ValidIPv6Range": {
			connection: config.FABRIDConnectionPoint{
				Type:      fabrid.IPv6Range,
				IPAddress: "2001:db8::2",
				Prefix:    56,
			},
			expectedType:   fabrid.IPv6Range,
			expectedIP:     "2001:db8::",
			expectedPrefix: 56,
			isError:        false,
		},
		"ValidWildcard": {
			connection: config.FABRIDConnectionPoint{
				Type: fabrid.Wildcard,
			},
			expectedType: fabrid.Wildcard,
			isError:      false,
		},
		"Invalid": {
			connection: config.FABRIDConnectionPoint{
				Type: "Invalid",
			},
			isError: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result, err := createConnectionPoint(tc.connection)
			if tc.isError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedType, result.Type)
			if result.Type == fabrid.IPv4Range || result.Type == fabrid.IPv6Range {
				require.Equal(t, tc.expectedIP, result.IP)
				require.Equal(t, tc.expectedPrefix, result.Prefix)
			} else if result.Type == fabrid.Interface {
				require.Equal(t, tc.expectedInterface, result.InterfaceId)
			}

		})
	}
}
