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

package graph

import "github.com/scionproto/scion/pkg/experimental/fabrid"

// FabridPolicy returns an arbitrary set of policies between between two interfaces of an AS.
func (g *Graph) FabridPolicy(a, b uint16) []*fabrid.Policy {
	if g.parents[a] != g.parents[b] && a != 0 && b != 0 {
		panic("interfaces must be in the same AS")
	}
	amtOfPols := int(a*b%10 + 3)
	policies := make([]*fabrid.Policy, amtOfPols)
	for i := 0; i < amtOfPols; i++ {
		policies[i] = &fabrid.Policy{
			IsLocal:    false,
			Identifier: (uint32(a)*uint32(b)*uint32(i)*39 + uint32(i) + 1) % 20000,
			Index:      fabrid.PolicyID(a * b),
		}
	}
	return policies
}
