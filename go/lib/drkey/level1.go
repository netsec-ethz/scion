// Copyright 2019 ETH Zurich
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

package drkey

import (
	"bytes"

	"github.com/scionproto/scion/go/lib/addr"
)

// Lvl1Meta represents the information about a level 1 DRKey other than the key itself.
type Lvl1Meta struct {
	Epoch Epoch
	SrcIA addr.IA
	DstIA addr.IA
}

// Equal returns true if both meta are identical.
func (m Lvl1Meta) Equal(other Lvl1Meta) bool {
	return m.Epoch.Equal(other.Epoch) && m.SrcIA.Equal(other.SrcIA) && m.DstIA.Equal(other.DstIA)
}

// Lvl1Key represents a level 1 DRKey.
type Lvl1Key struct {
	Lvl1Meta
	Key DRKey
}

// Equal returns true if both level 1 keys are identical.
func (k Lvl1Key) Equal(other Lvl1Key) bool {
	return k.Lvl1Meta.Equal(other.Lvl1Meta) && bytes.Compare(k.Key, other.Key) == 0
}
