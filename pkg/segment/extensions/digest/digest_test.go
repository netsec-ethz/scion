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

package digest_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"github.com/scionproto/scion/pkg/segment/extensions/epic"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

func TestDecodeEncode(t *testing.T) {
	hop := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	peers := make([][]byte, 0, 5)
	for i := 0; i < 5; i++ {
		peer := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
		peers = append(peers, peer)

		ed := &epic.Detached{
			AuthHopEntry:    hop,
			AuthPeerEntries: peers,
		}
		fd := &fabrid.Detached{
			SupportedIndicesMap: fabrid.SupportedIndicesMap{
				fabrid.ConnectionPair{
					Ingress: fabrid.ConnectionPoint{
						Type:   fabrid.IPv4Range,
						IP:     "192.168.2.100",
						Prefix: 22,
					},
					Egress: fabrid.ConnectionPoint{
						Type:        fabrid.Interface,
						InterfaceId: 44,
					}}: []uint8{1}},
			IndexIdentiferMap: fabrid.IndexIdentifierMap{
				1: &fabrid.PolicyIdentifier{
					IsLocal:    false,
					Identifier: 22,
				}},
		}

		var d digest.Digest
		input, err := ed.DigestInput()
		assert.NoError(t, err)
		d.Set(input)
		err = d.Validate(input)
		assert.NoError(t, err)

		var fabridDigest digest.Digest
		fabridDigest.Set(fd.Hash())
		err = fabridDigest.Validate(fd.Hash())
		assert.NoError(t, err)

		dig := &digest.Extension{
			Epic:   d,
			Fabrid: fabridDigest,
		}
		dig2 := digest.ExtensionFromPB(digest.ExtensionToPB(dig))
		assert.Equal(t, dig, dig2)
	}
}
