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

package hummingbird_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/stretchr/testify/assert"
)

var testHops = []hummingbird.BaseHop{
	{
		IA:      interfacesTest[0].IA,
		Ingress: 0,
		Egress:  1,
	},
	{
		IA:      interfacesTest[1].IA,
		Ingress: 2,
		Egress:  4,
	},
	{
		IA:      interfacesTest[len(interfacesTest)-1].IA,
		Ingress: 5,
		Egress:  0,
	},
}

var testFlyoversInDB = []hummingbird.Flyover{
	// For the first hop:
	{
		BaseHop:   testHops[0],
		ResID:     testFlyoverFieldsReserved[0].ResID + 1,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  70,
		StartTime: uint32(fixedTime.Unix()) - 80, // expired
	},
	{
		BaseHop: hummingbird.BaseHop{
			IA:      testHops[0].IA,
			Ingress: testHops[0].Ingress,
			Egress:  testHops[0].Egress + 1, // not the expected egress
		},
		ResID:     testFlyoverFieldsReserved[0].ResID + 2,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},
	{
		BaseHop:   testHops[0],
		ResID:     testFlyoverFieldsReserved[0].ResID + 3,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 1000, // expired
	},
	{
		BaseHop:   testHops[0],
		ResID:     testFlyoverFieldsReserved[0].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},

	// For the second hop:
	{
		BaseHop:   testHops[1],
		ResID:     testFlyoverFieldsReserved[1].ResID + 1,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
		Bw:        16,
		Duration:  180,
		StartTime: uint32(fixedTime.Unix()) - 1000, // expired
	},
	{
		BaseHop:   testHops[1],
		ResID:     testFlyoverFieldsReserved[1].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
		Bw:        16,
		Duration:  180,
		StartTime: uint32(fixedTime.Unix()) - 32,
	},

	// For the third hop:
	{
		BaseHop:   testHops[2],
		ResID:     testFlyoverFieldsReserved[3].ResID + 1,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        20,
		Duration:  150,
		StartTime: uint32(fixedTime.Unix()) + 1, // not yet valid
	},
	{
		BaseHop:   testHops[2],
		ResID:     testFlyoverFieldsReserved[3].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        testFlyoverFieldsReserved[3].Bw,
		Duration:  testFlyoverFieldsReserved[3].Duration,
		StartTime: uint32(fixedTime.Unix()) - 80,
	},
	{
		BaseHop:   testHops[2],
		ResID:     testFlyoverFieldsReserved[3].ResID + 2,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        testFlyoverFieldsReserved[3].Bw,
		Duration:  testFlyoverFieldsReserved[3].Duration,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},
}

var testExpectedFlyovers = []*hummingbird.Flyover{
	// For the first hop:
	{
		BaseHop:   testHops[0],
		ResID:     testFlyoverFieldsReserved[0].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},
	// For the second hop:
	{
		BaseHop:   testHops[1],
		ResID:     testFlyoverFieldsReserved[1].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
		Bw:        16,
		Duration:  180,
		StartTime: uint32(fixedTime.Unix()) - 32,
	},
	// for the third hop:
	nil,
	// For the fourth hop:
	{
		BaseHop:   testHops[2],
		ResID:     testFlyoverFieldsReserved[3].ResID,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        20,
		Duration:  150,
		StartTime: uint32(fixedTime.Unix()) - 80,
	},
}

func TestConvertToHbirdPath(t *testing.T) {
	scionPath := getScionSnetPath(t)

	now := time.Now()
	expectecPath, err := getHbirdNoFlyoversSnetPath(now)
	assert.NoError(t, err)

	out, err := hummingbird.ConvertToHbirdPath(scionPath, now)
	assert.NoError(t, err)
	assert.Equal(t, expectecPath, out)
}
