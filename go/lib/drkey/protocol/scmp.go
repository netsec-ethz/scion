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

package protocol

import (
	"github.com/scionproto/scion/go/lib/drkey"
)

var _ Derivation = scmp{}

// scmp implements the derivation for the SCMP protocol.
type scmp struct{}

// Name returns scmp.
func (scmp) Name() string {
	return "scmp"
}

// DeriveLvl2 uses the standard derivation.
func (scmp) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	return Standard{}.DeriveLvl2(meta, key)
}

func init() {
	s := scmp{}
	KnownDerivations[s.Name()] = s
}
