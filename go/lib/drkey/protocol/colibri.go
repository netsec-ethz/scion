// Copyright 2021 ETH Zurich
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

var _ DelegatedDerivation = colibri{}

func init() {
	p := colibri{}
	KnownDerivations[p.Name()] = p
}

// colibri implements the derivation for the COLIBRI source authentication protocol.
type colibri struct{}

// Name returns scmp.
func (colibri) Name() string {
	return "colibri"
}

// DeriveLvl2 uses the standard derivation.
func (colibri) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	return Delegated{}.DeriveLvl2(meta, key)
}

func (colibri) DeriveLvl2FromDS(meta drkey.Lvl2Meta, ds drkey.DelegationSecret) (
	drkey.Lvl2Key, error) {

	return Delegated{}.DeriveLvl2FromDS(meta, ds)
}
