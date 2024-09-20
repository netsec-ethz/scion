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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

func TestEqualHashDifferentInsertionOrders(t *testing.T) {
	type insertionInput struct {
		CP        fabrid.ConnectionPair
		mplsLabel uint32
		polIdx    uint8
	}

	input := []insertionInput{
		{
			CP: fabrid.ConnectionPair{
				Ingress: fabrid.ConnectionPoint{
					Type:        fabrid.Interface,
					InterfaceId: 10,
				},
				Egress: fabrid.ConnectionPoint{
					Type:        fabrid.Interface,
					InterfaceId: 20,
				},
			},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
			Egress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},

		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
			Egress: fabrid.ConnectionPoint{
				Type:   fabrid.IPv4Range,
				IP:     "192.168.1.0",
				Prefix: 24,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type:   fabrid.IPv4Range,
				IP:     "192.168.1.0",
				Prefix: 24,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},

		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
	}

	m := NewMplsMaps()
	for _, i := range input {
		m.AddConnectionPoint(i.CP, i.mplsLabel, i.polIdx)
	}
	m.UpdateHash()
	baseHash := m.CurrentHash
	rand.New(rand.NewSource(42))

	for round := 0; round < 10; round++ {
		m = NewMplsMaps()
		rand.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		for _, i := range input {
			m.AddConnectionPoint(i.CP, i.mplsLabel, i.polIdx)
		}

		m.UpdateHash()
		require.Equal(t, baseHash, m.CurrentHash)
	}
}

func TestHashChanges(t *testing.T) {

	type insertionInput struct {
		CP        fabrid.ConnectionPair
		mplsLabel uint32
		polIdx    uint8
	}

	input := []insertionInput{
		{
			CP: fabrid.ConnectionPair{
				Ingress: fabrid.ConnectionPoint{
					Type:        fabrid.Interface,
					InterfaceId: 10,
				},
				Egress: fabrid.ConnectionPoint{
					Type:        fabrid.Interface,
					InterfaceId: 20,
				},
			},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
			Egress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},

		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: 3,
			},
			Egress: fabrid.ConnectionPoint{
				Type:   fabrid.IPv4Range,
				IP:     "192.168.1.0",
				Prefix: 24,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type:   fabrid.IPv4Range,
				IP:     "192.168.1.0",
				Prefix: 24,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},

		{CP: fabrid.ConnectionPair{
			Ingress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
			Egress: fabrid.ConnectionPoint{
				Type: fabrid.Wildcard,
			},
		},
			mplsLabel: 21902,
			polIdx:    20,
		},
	}

	rand.New(rand.NewSource(42))

	for round := 0; round < 10; round++ {
		m := NewMplsMaps()
		rand.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		prevHashes := make([][]byte, len(input))
		for j, i := range input {
			m.AddConnectionPoint(i.CP, i.mplsLabel, i.polIdx)
			m.UpdateHash()
			require.NotContains(t, prevHashes, m.CurrentHash)
			prevHashes[j] = m.CurrentHash
		}
	}
}
