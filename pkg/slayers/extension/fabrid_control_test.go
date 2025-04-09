// Copyright 2023 ETH Zurich
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

func TestFabridControlDecode(t *testing.T) {
	type test struct {
		name     string
		o        *slayers.EndToEndOption
		validate func(*extension.FabridControlOption, error, *testing.T)
	}
	tests := []test{
		{
			name: "Wrong option type",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: make([]byte, 4),
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Wrong fabrid control option type",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{0x50},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid too short",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: make([]byte, 4),
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid parses with correct length",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: make([]byte, 5),
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Parses fabrid validation config correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x0F, 0x22, 0x33, 0x44,
					0xaa,
				},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.ValidationConfig, fco.Type, "Wrong type")
				assert.Equal(t, [4]byte{0x0F, 0x22, 0x33, 0x44}, fco.Auth, "Wrong auth")
				assert.Equal(t, []byte{0xaa}, fco.Data, "Wrong data")
			},
		},
		{
			name: "Parses fabrid validation config ACK correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x1f, 0x22, 0x33, 0x44,
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11,
				},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.ValidationConfigAck, fco.Type, "Wrong type")
				assert.Equal(t, [4]byte{0x0F, 0x22, 0x33, 0x44}, fco.Auth, "Wrong auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11}, fco.Data, "Wrong data")
			},
		},
		{
			name: "Parses fabrid validation response correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x2f, 0x22, 0x33, 0x44,
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0xcc, 0xdd, 0xee, 0xff,
				},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.ValidationResponse, fco.Type, "Wrong type")
				assert.Equal(t, [4]byte{0x0f, 0x22, 0x33, 0x44}, fco.Auth, "Wrong auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0xcc, 0xdd, 0xee, 0xff},
					fco.Data, "Wrong path validator reply")
			},
		},
		{
			name: "Parses fabrid statistics request correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x3f, 0x22, 0x33, 0x44,
				},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.StatisticsRequest, fco.Type, "Wrong type")
				assert.Equal(t, [4]byte{0x0f, 0x22, 0x33, 0x44}, fco.Auth, "Wrong auth")
				assert.Empty(t, fco.Data, "Wrong data")
			},
		},
		{
			name: "Parses fabrid statistics response correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x4f, 0x22, 0x33, 0x44,
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0xaa, 0xbb, 0xcc, 0xdd,
					0x0a, 0x0b, 0x0c, 0x0d,
				},
			},
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.StatisticsResponse, fco.Type, "Wrong type")
				assert.Equal(t, [4]byte{0x0f, 0x22, 0x33, 0x44}, fco.Auth, "Wrong auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0xaa, 0xbb, 0xcc, 0xdd,
					0x0a, 0x0b, 0x0c, 0x0d,
				}, fco.Data, "Wrong data")
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fc, err := extension.ParseFabridControlOption(tc.o)
				tc.validate(fc, err, t)
			})
		}(tc)
	}
}

func TestFabridControlSerialize(t *testing.T) {
	type test struct {
		name     string
		fc       *extension.FabridControlOption
		buffer   []byte
		validate func([]byte, error, *testing.T)
	}

	tests := []test{
		{
			name: "Fabrid control option is nil",
			fc:   nil,
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Buffer too small",
			fc: &extension.FabridControlOption{
				Type: extension.ValidationConfig,
				Data: make([]byte, 1),
			},
			buffer: make([]byte, 4),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Data buffer too small",
			fc: &extension.FabridControlOption{
				Type: extension.ValidationConfig,
			},
			buffer: make([]byte, 5),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Fabrid validation config serializes correctly",
			fc: &extension.FabridControlOption{
				Type: extension.ValidationConfig,
				Auth: [4]byte{0x07, 0xb2, 0xc3, 0xd4},
				Data: []byte{0x99},
			},
			buffer: make([]byte, 5),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x07, 0xb2, 0xc3, 0xd4}, b[0:4], "Wrong type or Auth")
				assert.Equal(t, []byte{0x99}, b[4:5], "Wrong Data")
			},
		},
		{
			name: "Fabrid validation configuration ACK serializes correctly",
			fc: &extension.FabridControlOption{
				Type: extension.ValidationConfigAck,
				Auth: [4]byte{0x0f, 0xb2, 0xc3, 0xd4},
				Data: []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11},
			},
			buffer: make([]byte, 13),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x1f, 0xb2, 0xc3, 0xd4}, b[0:4], "Wrong type or Auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11}, b[4:13], "Wrong Data")
			},
		},
		{
			name: "Fabrid validation response serializes correctly",
			fc: &extension.FabridControlOption{
				Type: extension.ValidationResponse,
				Auth: [4]byte{0x0f, 0xb2, 0xc3, 0xd4},
				Data: []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11, 0x00, 0x99, 0x88},
			},
			buffer: make([]byte, 16),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x2f, 0xb2, 0xc3, 0xd4}, b[0:4], "Wrong type or Auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x11, 0x00, 0x99, 0x88,
				}, b[4:16], "Wrong Data")
			},
		},
		{
			name: "Fabrid statistics request serializes correctly",
			fc: &extension.FabridControlOption{
				Type: extension.StatisticsRequest,
				Auth: [4]byte{0x0f, 0xb2, 0xc3, 0xd4},
			},
			buffer: make([]byte, 4),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x3f, 0xb2, 0xc3, 0xd4}, b[0:4], "Wrong type or Auth")
			},
		},
		{
			name: "Fabrid statistics response serializes correctly",
			fc: &extension.FabridControlOption{
				Type: extension.StatisticsResponse,
				Auth: [4]byte{0x0f, 0xb2, 0xc3, 0xd4},
				Data: []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x99, 0x88, 0x77, 0x66,
					0x55, 0x44, 0x33, 0x22},
			},
			buffer: make([]byte, 20),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x4f, 0xb2, 0xc3, 0xd4}, b[0:4], "Wrong type or Auth")
				assert.Equal(t, []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x99, 0x88, 0x77, 0x66,
					0x55, 0x44, 0x33, 0x22,
				}, b[4:20], "Wrong Data")
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := tc.fc.SerializeTo(tc.buffer)
				tc.validate(tc.buffer, err, t)
			})
		}(tc)
	}
}
