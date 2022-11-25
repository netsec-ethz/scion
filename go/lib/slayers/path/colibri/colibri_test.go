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
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

func TestColibriSerializeDecode(t *testing.T) {
	colPath := newColibriPath()
	// use the colPath colibri path but chop it to hfCount hop fields:
	for hfCount := 2; hfCount <= int(colPath.InfoField.HFCount); hfCount++ {
		col := newColibriPath()
		// Set correct number of hop fields
		col.HopFields = col.HopFields[:hfCount]
		col.InfoField.HFCount = uint8(hfCount)

		buff := make([]byte, col.Len())
		assert.NoError(t, col.SerializeTo(buff))
		// assert.Equal(t, buffer, buffer2)
		col2 := &colibri.ColibriPath{}
		assert.NoError(t, col2.DecodeFromBytes(buff))

		// Test ColibriPathMinimal
		colMin := &colibri.ColibriPathMinimal{}
		colMin2 := &colibri.ColibriPathMinimal{}
		assert.NoError(t, colMin.DecodeFromBytes(buff))
		buff = make([]byte, colMin.Len())
		assert.NoError(t, colMin.SerializeTo(buff))
		assert.NoError(t, colMin2.DecodeFromBytes(buff))
		assert.Equal(t, colMin, colMin2)
	}
}

func TestColibriReverse(t *testing.T) {
	colPath := newColibriPath()
	// use the colPath colibri path but chop it to hfCount hop fields:
	for hfCount := 2; hfCount <= int(colPath.InfoField.HFCount); hfCount++ {
		new := newColibriPath()
		old := newColibriPath()
		// Set correct number of hop fields
		new.HopFields = new.HopFields[:hfCount]
		new.InfoField.HFCount = uint8(hfCount)
		old.HopFields = old.HopFields[:hfCount]
		old.InfoField.HFCount = uint8(hfCount)

		_, err := new.Reverse()
		assert.NoError(t, err)

		assert.Equal(t, old.InfoField.R, !new.InfoField.R)
		for j := 0; j < hfCount/2+1; j++ {
			assert.Equal(t, old.HopFields[j].Mac, new.HopFields[hfCount-j-1].Mac)
			assert.Equal(t, old.HopFields[j].IngressId, new.HopFields[hfCount-j-1].EgressId)
		}

		// reverse again
		_, err = new.Reverse()
		assert.NoError(t, err)
		assert.Equal(t, new, old)
	}
}

// TestPathToBytesAndReverse checks that the path can be serialized and reversed. It prints
// the bytes in hex, to be used as input in other tests that require a valid colibri path.
func TestPathToBytesAndReverse(t *testing.T) {
	p := newColibriPath()
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

func newColibriPath() *colibri.ColibriPath {
	p := &colibri.ColibriPath{
		PacketTimestamp: [8]byte{},
		InfoField: &colibri.InfoField{
			Ver:         7,
			CurrHF:      1,
			HFCount:     5,
			ResIdSuffix: make([]byte, 12),
			BwCls:       19,
			OrigPayLen:  1342,
		},
		HopFields: make([]*colibri.HopField, 5),
	}
	for i := range p.HopFields {
		p.HopFields[i] = &colibri.HopField{
			IngressId: uint16(2 * i),
			EgressId:  uint16(2*i + 1),
			Mac:       make([]byte, 4),
		}
		binary.BigEndian.PutUint32(p.HopFields[i].Mac, uint32(i))
	}
	return p
}
