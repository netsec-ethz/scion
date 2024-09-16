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

package router

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/router/control"
)

func TestFabridPolicies(t *testing.T) {
	type testcase struct {
		name              string
		ipRangePolicies   map[uint32][]*control.PolicyIPRange
		interfacePolicies map[uint64]uint32
		packetIngress     uint32
		packetEgress      uint32
		useIPRange        bool
		packetPolicyIndex uint32
		nextHopIP         net.IP
		expectedMplsLabel uint32
		expectsError      bool
	}
	testcases := []testcase{
		{
			name: "ingress and policyindex tuple exists with single ip range",
			ipRangePolicies: map[uint32][]*control.PolicyIPRange{
				0xa<<8 + 0xf: {
					&control.PolicyIPRange{
						MPLSLabel: 1,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.0/24"),
					},
				},
			},
			expectedMplsLabel: 1,
			packetIngress:     0xa,
			packetPolicyIndex: 0xf,
			nextHopIP:         xtest.MustParseIP(t, "127.0.0.1"),
			useIPRange:        true,
		},
		{
			name:              "ingress and policyindex tuple doesn't exist",
			ipRangePolicies:   map[uint32][]*control.PolicyIPRange{},
			expectedMplsLabel: 1,
			packetIngress:     0xa,
			packetPolicyIndex: 0xf,
			nextHopIP:         xtest.MustParseIP(t, "127.0.0.1"),
			expectsError:      true,
			useIPRange:        true,
		},
		{
			name: "ingress and policyindex tuple exists with multiple ip ranges",
			ipRangePolicies: map[uint32][]*control.PolicyIPRange{
				0xa<<8 + 0xf: {
					&control.PolicyIPRange{
						MPLSLabel: 1,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.0/24"),
					},
					&control.PolicyIPRange{
						MPLSLabel: 2,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.0/31"),
					},
					&control.PolicyIPRange{
						MPLSLabel: 3,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.0/30"),
					},
					&control.PolicyIPRange{
						MPLSLabel: 4,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.2/32"),
					},
				},
			},
			expectedMplsLabel: 2,
			packetIngress:     0xa,
			packetPolicyIndex: 0xf,
			nextHopIP:         xtest.MustParseIP(t, "127.0.0.1"),
			useIPRange:        true,
		},
		{
			name: "ip range only exists for default value",
			ipRangePolicies: map[uint32][]*control.PolicyIPRange{
				1<<31 + 0xf: {
					&control.PolicyIPRange{
						MPLSLabel: 1,
						IPPrefix:  xtest.MustParseCIDR(t, "127.0.0.0/24"),
					},
				},
			},
			expectedMplsLabel: 1,
			packetIngress:     0xa,
			packetPolicyIndex: 0xf,
			nextHopIP:         xtest.MustParseIP(t, "127.0.0.1"),
			useIPRange:        true,
		},
		{
			name: "mpls label exists for interface map",
			interfacePolicies: map[uint64]uint32{
				1<<24 + 2<<8 + 0xf: 7,
				1<<63 + 2<<8 + 0xf: 5, // default value
			},
			expectedMplsLabel: 7,
			packetIngress:     1,
			packetEgress:      2,
			packetPolicyIndex: 0xf,
			useIPRange:        false,
		},
		{
			name: "mpls label exists for interface map with default value",
			interfacePolicies: map[uint64]uint32{
				1<<63 + 2<<8 + 0xf: 5, // default value
			},
			expectedMplsLabel: 5,
			packetIngress:     1,
			packetEgress:      2,
			packetPolicyIndex: 0xf,
			useIPRange:        false,
		},
		{
			name:              "mpls label doesnt exist for interface map",
			interfacePolicies: map[uint64]uint32{},
			packetIngress:     1,
			packetEgress:      2,
			packetPolicyIndex: 0xf,
			expectsError:      true,
			useIPRange:        false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dp := &DataPlane{Metrics: metrics}
			err := dp.UpdateFabridPolicies(tc.ipRangePolicies, tc.interfacePolicies)
			assert.NoError(t, err)
			var mplsLabel uint32
			if tc.useIPRange {
				mplsLabel, err = dp.getFabridMplsLabel(tc.packetIngress, tc.packetPolicyIndex,
					tc.nextHopIP)
			} else {
				mplsLabel, err = dp.getFabridMplsLabelForInterface(tc.packetIngress,
					tc.packetPolicyIndex, tc.packetEgress)
			}
			if tc.expectsError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMplsLabel, mplsLabel)
			}
		})
	}

}
