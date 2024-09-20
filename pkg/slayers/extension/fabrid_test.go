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

package extension_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
)

func TestFabridDecode(t *testing.T) {
	type test struct {
		name     string
		o        *slayers.HopByHopOption
		currHf   uint8
		numHfs   uint8
		validate func(*extension.FabridOption, error, *testing.T)
	}
	tests := []test{
		{
			name: "wrong option type",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: make([]byte, 8),
			},
			currHf: 1,
			numHfs: 1,
			validate: func(fo *extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid too short",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 11),
			},
			currHf: 1,
			numHfs: 2,
			validate: func(fo *extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid parses with 62 HF",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 252),
			},
			currHf: 1,
			numHfs: extension.MaxSupportedFabridHops,
			validate: func(fo *extension.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Raw fabrid fails parsing 63 HF",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 1000),
			},
			currHf: 1,
			numHfs: extension.MaxSupportedFabridHops + 1,
			validate: func(fo *extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Parses fabrid correctly",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: []byte{
					0x66, 0x37, 0x88, 0x99,
					0xaa, 0x8b, 0xcc, 0xdd,
					0xaa, 0xc1, 0x01, 0x01,
					0x22, 0x33, 0x44, 0x55,
				},
			},
			currHf: 1,
			numHfs: 3,
			validate: func(fo *extension.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, 3, len(fo.HopfieldMetadata))
				assert.Equal(t, uint8(0x66), fo.HopfieldMetadata[0].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0x37, 0x88, 0x99},
					fo.HopfieldMetadata[0].HopValidationField)
				assert.Equal(t, false, fo.HopfieldMetadata[0].FabridEnabled)
				assert.Equal(t, false, fo.HopfieldMetadata[0].ASLevelKey)
				assert.Equal(t, uint8(0xaa), fo.HopfieldMetadata[1].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0x0b, 0xcc, 0xdd},
					fo.HopfieldMetadata[1].HopValidationField)
				assert.Equal(t, true, fo.HopfieldMetadata[1].FabridEnabled)
				assert.Equal(t, false, fo.HopfieldMetadata[1].ASLevelKey)
				assert.Equal(t, uint8(0xaa), fo.HopfieldMetadata[2].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0x01, 0x01, 0x01},
					fo.HopfieldMetadata[2].HopValidationField)
				assert.Equal(t, true, fo.HopfieldMetadata[2].FabridEnabled)
				assert.Equal(t, true, fo.HopfieldMetadata[2].ASLevelKey)
				assert.Equal(t, [4]byte{0x22, 0x33, 0x44, 0x55}, fo.PathValidator)
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f, err := extension.ParseFabridOptionFullExtension(tc.o, tc.numHfs)
				tc.validate(f, err, t)
			})
		}(tc)
	}
}

func TestFabridSerialize(t *testing.T) {
	type test struct {
		name     string
		fabrid   *extension.FabridOption
		buffer   []byte
		validate func([]byte, error, *testing.T)
	}

	tests := []test{
		{
			name:   "Fabrid option is nil",
			fabrid: nil,
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Buffer too small",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: make([]*extension.FabridHopfieldMetadata, 1),
			},
			buffer: make([]byte, 7),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Too many hops",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: make([]*extension.FabridHopfieldMetadata,
					extension.MaxSupportedFabridHops+1),
			},
			buffer: make([]byte, 256),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Fabrid serializes correctly",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: []*extension.FabridHopfieldMetadata{
					{
						EncryptedPolicyID:  0x11,
						HopValidationField: [3]byte{0x22, 0x33, 0x44},
					},
					{
						EncryptedPolicyID:  0xaa,
						FabridEnabled:      true,
						HopValidationField: [3]byte{0x0b, 0xcc, 0xdd},
					},
					{
						EncryptedPolicyID:  0xaa,
						FabridEnabled:      true,
						ASLevelKey:         true,
						HopValidationField: [3]byte{0x01, 0x01, 0x01},
					},
				},
				PathValidator: [4]byte{0x11, 0x22, 0x33, 0x44},
			},
			buffer: make([]byte, 16),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, b[0:4])   //HF1 without F or A
				assert.Equal(t, []byte{0xaa, 0x8b, 0xcc, 0xdd}, b[4:8])   //HF2 with F without A
				assert.Equal(t, []byte{0xaa, 0xc1, 0x01, 0x01}, b[8:12])  //HF3 with F and A
				assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, b[12:16]) //Path validator
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := tc.fabrid.SerializeTo(tc.buffer)
				tc.validate(tc.buffer, err, t)
			})
		}(tc)
	}
}
