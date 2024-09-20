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
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
)

func TestIdentifierDecode(t *testing.T) {
	type test struct {
		name          string
		o             *slayers.HopByHopOption
		baseTimestamp uint32
		validate      func(*extension.IdentifierOption, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name: "wrong option type",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: []byte{
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x0,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id *extension.IdentifierOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "raw data too short",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: []byte{
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id *extension.IdentifierOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "correct timestamp",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: []byte{
					0xff, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id *extension.IdentifierOption, err error, t *testing.T) {
				assert.NoError(t, err)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, id.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), id.PacketID)
			},
		},
	}
	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				id, err := extension.ParseIdentifierOption(tc.o, tc.baseTimestamp)
				tc.validate(id, err, t)
			})
		}(tc)
	}
}

func TestIdentifierSerialize(t *testing.T) {
	type test struct {
		name       string
		identifier *extension.IdentifierOption
		buffer     []byte
		validate   func([]byte, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name:       "identifier is nil",
			identifier: nil,
			buffer:     make([]byte, 100),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name:       "buffer too small",
			identifier: &extension.IdentifierOption{},
			buffer:     make([]byte, 7),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "correct serialization",
			identifier: &extension.IdentifierOption{
				Timestamp:     time.Unix(int64(unixNow), 0x7000001*int64(time.Millisecond)),
				PacketID:      0xaabbccdd,
				BaseTimestamp: unixNow,
			},
			buffer: make([]byte, 8),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x7, 0x00, 0x00, 0x01}, b[0:4]) //the timestamp
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8])
			},
		},
	}
	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := tc.identifier.Serialize(tc.buffer)
				tc.validate(tc.buffer, err, t)
			})
		}(tc)
	}
}
