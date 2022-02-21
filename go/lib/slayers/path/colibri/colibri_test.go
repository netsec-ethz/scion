// Copyright 2020 ETH Zurich
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

package colibri_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/xtest"
)

var randSlice = xtest.MustParseHexString("fe31a2e94699ede20df7edaefd8042d866bf3a4c1a7f2be603973f" +
	"f077c3a6366c7933170974efeeec1dc88ba2bf6f88f86dd34b158cd8c176b4b1cd965ee1e093336a667952eb38e" +
	"fa8ff1618e9f809499a578e26f23b68cfbb56a5a7cdd7b2c0f974e43c14fbc22ef2f4ea25e2224649304a961d3e" +
	"2867c3cb8bf92ba7bd0f")

func TestColibriSerializeDecode(t *testing.T) {
	for i := 2; i < 11; i++ {
		bufferLength := 8 + colibri.LenInfoField + i*colibri.LenHopField
		buffer := randSlice[:bufferLength]
		// Remove the "reserved" flags from the info field
		buffer[8] = buffer[8] & uint8(0xE0)
		buffer[9] = 0
		buffer[30] = buffer[30] & uint8(0xF0)
		buffer[31] = 0
		// Set correct number of hop fields
		buffer[10] = uint8(i - 1)
		buffer[11] = uint8(i)

		// Test ColibriPath
		col := &colibri.ColibriPath{}
		assert.NoError(t, col.DecodeFromBytes(buffer))

		buffer2 := make([]byte, col.Len())
		assert.NoError(t, col.SerializeTo(buffer2))
		assert.Equal(t, buffer, buffer2)

		// Test ColibriPathMinimal
		colMin := &colibri.ColibriPathMinimal{}
		colMin2 := &colibri.ColibriPathMinimal{}
		assert.NoError(t, colMin.DecodeFromBytes(buffer))
		buffer2 = make([]byte, colMin.Len())
		assert.NoError(t, colMin.SerializeTo(buffer2))
		assert.NoError(t, colMin2.DecodeFromBytes(buffer2))
		assert.Equal(t, colMin, colMin2)
	}
}

func TestColibriReverse(t *testing.T) {
	for i := 2; i < 11; i++ {
		bufferLength := 8 + colibri.LenInfoField + i*colibri.LenHopField
		buffer := randSlice[:bufferLength]
		// Set correct number of hop fields
		buffer[10] = uint8(i - 1)
		buffer[11] = uint8(i)

		old := &colibri.ColibriPath{}
		new := &colibri.ColibriPath{}
		assert.NoError(t, old.DecodeFromBytes(buffer))
		assert.NoError(t, new.DecodeFromBytes(buffer))

		rev, err := new.Reverse()
		new = rev.(*colibri.ColibriPath)
		assert.NoError(t, err)

		assert.Equal(t, old.InfoField.R, !new.InfoField.R)
		for j := 0; j < i/2+1; j++ {
			assert.Equal(t, old.HopFields[j], new.HopFields[i-1-j])
		}

		revrev, err2 := rev.Reverse()
		assert.NoError(t, err2)
		assert.Equal(t, revrev, old)
	}
}

// TestPathToBytesAndReverse checks that the path can be serialized and reversed. It prints
// the bytes in hex, to be used as input in other tests that require a valid colibri path.
func TestPathToBytesAndReverse(t *testing.T) {
	p := &colibri.ColibriPath{
		InfoField: &colibri.InfoField{
			ResIdSuffix: xtest.MustParseHexString("0123456789ab0123456789ab"), // 12 bytes
			BwCls:       13,
			HFCount:     3,
			CurrHF:      0,
		},
		HopFields: []*colibri.HopField{
			{
				IngressId: 0,
				EgressId:  1,
				Mac:       xtest.MustParseHexString("01234567"),
			},
			{
				IngressId: 1,
				EgressId:  2,
				Mac:       xtest.MustParseHexString("01234567"),
			},
			{
				IngressId: 1,
				EgressId:  0,
				Mac:       xtest.MustParseHexString("01234567"),
			},
		},
	}
	buff := make([]byte, p.Len())
	require.NoError(t, p.SerializeTo(buff))
	t.Log("colibri path", hex.EncodeToString(buff))

	rp, err := p.Reverse()
	require.NoError(t, err)
	require.IsType(t, &colibri.ColibriPath{}, rp)
	p = rp.(*colibri.ColibriPath)
	buff = make([]byte, p.Len())
	require.NoError(t, p.SerializeTo(buff))
	t.Log("reversed colibri path", hex.EncodeToString(buff))
}
