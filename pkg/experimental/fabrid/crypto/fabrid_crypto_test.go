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

package crypto_test

import (
	crand "crypto/rand"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
)

func TestEncryptPolicyID(t *testing.T) {
	unixNow := uint32(time.Now().Unix())

	id := &extension.IdentifierOption{
		Timestamp:     time.Unix(int64(unixNow), 10*int64(time.Millisecond)),
		PacketID:      0xaa,
		BaseTimestamp: unixNow,
	}
	// test with 64 different randomly chosen keys and policyIDs
	for i := 0; i < 64; i++ {
		policyID := fabrid.PolicyID(rand.Uint32())
		key := generateRandomBytes(16)
		encPolicyID, err := crypto.EncryptPolicyID(policyID, id, key)
		assert.NoError(t, err)
		meta := &extension.FabridHopfieldMetadata{
			EncryptedPolicyID:  encPolicyID,
			HopValidationField: [3]byte{},
		}
		computedPolicyID, err := crypto.ComputePolicyID(meta, id, key)
		assert.NoError(t, err)
		assert.Equal(t, policyID, computedPolicyID)
	}
}

func generateRandomBytes(len int) []byte {
	b := make([]byte, len)
	_, _ = crand.Read(b)
	return b
}

func TestFailedValidation(t *testing.T) {
	type test struct {
		name    string
		runTest func(t *testing.T)
	}
	tests := []test{
		{
			name: "manipulated hopfield leads to failed path validator",
			runTest: func(t *testing.T) {
				unixNow := uint32(time.Now().Unix())
				tmpBuffer := make([]byte, (extension.MaxSupportedFabridHops*3+15)&^15+16)
				id := &extension.IdentifierOption{
					Timestamp:     time.Unix(int64(unixNow), 10*int64(time.Millisecond)),
					PacketID:      rand.Uint32(),
					BaseTimestamp: unixNow,
				}
				s := &slayers.SCION{
					RawSrcAddr: generateRandomBytes(4),
					SrcIA:      addr.MustIAFrom(1, 1),
				}
				f := &extension.FabridOption{}
				f.HopfieldMetadata = append(f.HopfieldMetadata,
					&extension.FabridHopfieldMetadata{
						EncryptedPolicyID: uint8(rand.Uint32()),
						FabridEnabled:     true,
						ASLevelKey:        rand.Intn(2) == 0,
					})
				pathKey := &drkey.FabridKey{
					Key: drkey.Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				}
				asHostKeys := make(map[addr.IA]*drkey.FabridKey)
				asAsKeys := make(map[addr.IA]*drkey.FabridKey)
				hops := make([]snet.HopInterface, len(f.HopfieldMetadata))

				for i := 0; i < len(f.HopfieldMetadata); i++ {
					hops[i] = snet.HopInterface{
						IgIf:     common.IFIDType(rand.Int()),
						EgIf:     common.IFIDType(rand.Int()),
						Policies: nil,
					}
					if i == 0 {
						hops[i].IA = addr.MustIAFrom(1, 1)
					} else {
						hops[i].IA = addr.IA(rand.Int())
					}
					keyBytes := drkey.Key{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
					if f.HopfieldMetadata[i].ASLevelKey {
						asAsKeys[hops[i].IA] = &drkey.FabridKey{Key: keyBytes}
					} else {
						asHostKeys[hops[i].IA] = &drkey.FabridKey{Key: keyBytes}
					}
				}

				err := crypto.InitValidators(f, id, s, tmpBuffer, pathKey, asHostKeys,
					asAsKeys, hops)
				assert.NoError(t, err)

				for i, meta := range f.HopfieldMetadata {
					if meta.FabridEnabled {
						if meta.ASLevelKey {
							key := asAsKeys[hops[i].IA]
							err = crypto.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:],
								uint16(hops[i].IgIf), uint16(hops[i].EgIf))
						} else {
							key := asHostKeys[hops[i].IA]
							err = crypto.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:],
								uint16(hops[i].IgIf), uint16(hops[i].EgIf),
							)
						}

						assert.NoError(t, err)
					}
				}
				_, err = crypto.VerifyPathValidator(f, tmpBuffer, pathKey.Key[:])
				assert.NoError(t, err)
				// until now we are in the success case. But now we modify a HVF to simulate
				// adversarial actions and make sure that the path validator fails
				f.HopfieldMetadata[0].HopValidationField = [3]byte{0, 0, 0}
				_, err = crypto.VerifyPathValidator(f, tmpBuffer, pathKey.Key[:])
				assert.ErrorContains(t, err, "Path validator is not valid")
			},
		},
		{
			name: "verify hopfield fails for wrong value",
			runTest: func(t *testing.T) {
				f := &extension.FabridOption{
					HopfieldMetadata: []*extension.FabridHopfieldMetadata{
						{
							FabridEnabled:      true,
							HopValidationField: [3]byte{1, 2, 3},
						},
					},
				}
				id := &extension.IdentifierOption{}
				s := &slayers.SCION{}
				tmpBuffer := make([]byte, 128)
				hfKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				err := crypto.VerifyAndUpdate(f.HopfieldMetadata[0], id, s, tmpBuffer, hfKey, 1, 2)
				assert.ErrorContains(t, err, "HVF is not valid")
			},
		},
	}
	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, tc.runTest)
		}(tc)
	}
}

func TestSuccessfullValidators(t *testing.T) {
	type test struct {
		name       string
		rawSrcAddr []byte
		srcIA      addr.IA
	}
	unixNow := uint32(time.Now().Unix())

	tmpBuffer := make([]byte, (extension.MaxSupportedFabridHops*3+15)&^15+16)
	tests := []test{
		{
			name:       "random 16 byte src addr",
			rawSrcAddr: generateRandomBytes(16),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 12 byte src addr",
			rawSrcAddr: generateRandomBytes(12),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 8 byte src addr",
			rawSrcAddr: generateRandomBytes(8),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 4 byte src addr",
			rawSrcAddr: generateRandomBytes(4),
			srcIA:      addr.IA(rand.Uint64()),
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				id := &extension.IdentifierOption{
					Timestamp:     time.Unix(int64(unixNow), 10*int64(time.Millisecond)),
					PacketID:      rand.Uint32(),
					BaseTimestamp: unixNow,
				}
				s := &slayers.SCION{
					RawSrcAddr: tc.rawSrcAddr,
					SrcIA:      tc.srcIA,
				}
				f := &extension.FabridOption{}
				for j := uint8(1); j <= extension.MaxSupportedFabridHops; j++ {
					f.HopfieldMetadata = append(f.HopfieldMetadata,
						&extension.FabridHopfieldMetadata{
							EncryptedPolicyID: uint8(rand.Uint32()),
							FabridEnabled:     rand.Intn(2) == 0,
							ASLevelKey:        rand.Intn(2) == 0,
						})
					keyBytes := drkey.Key{}
					copy(keyBytes[:], generateRandomBytes(16))
					pathKey := &drkey.FabridKey{Key: keyBytes}
					asHostKeys := make(map[addr.IA]*drkey.FabridKey)
					asAsKeys := make(map[addr.IA]*drkey.FabridKey)
					hops := make([]snet.HopInterface, len(f.HopfieldMetadata))

					for i := 0; i < len(f.HopfieldMetadata); i++ {
						hops[i] = snet.HopInterface{
							IgIf:     common.IFIDType(rand.Int()),
							EgIf:     common.IFIDType(rand.Int()),
							Policies: nil,
						}
						if i == 0 {
							hops[i].IA = tc.srcIA
						} else {
							hops[i].IA = addr.IA(rand.Int())
						}
						keyBytes = drkey.Key{}
						copy(keyBytes[:], generateRandomBytes(16))
						if f.HopfieldMetadata[i].ASLevelKey {
							asAsKeys[hops[i].IA] = &drkey.FabridKey{Key: keyBytes}
						} else {
							asHostKeys[hops[i].IA] = &drkey.FabridKey{Key: keyBytes}
						}
					}

					err := crypto.InitValidators(f, id, s, tmpBuffer, pathKey, asHostKeys,
						asAsKeys, hops)
					assert.NoError(t, err)

					for i, meta := range f.HopfieldMetadata {
						if meta.FabridEnabled {

							if meta.ASLevelKey {
								key := asAsKeys[hops[i].IA]
								err = crypto.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:],
									uint16(hops[i].IgIf), uint16(hops[i].EgIf))
							} else {
								key := asHostKeys[hops[i].IA]
								err = crypto.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:],
									uint16(hops[i].IgIf), uint16(hops[i].EgIf),
								)
							}

							assert.NoError(t, err)
						}
					}
					_, err = crypto.VerifyPathValidator(f, tmpBuffer, pathKey.Key[:])
					assert.NoError(t, err)
				}
			})
		}(tc)
	}
}
