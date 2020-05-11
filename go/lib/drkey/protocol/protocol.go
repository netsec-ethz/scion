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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Derivation specifies the interface to implement for a derivation method.
type Derivation interface {
	Name() string
	DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error)
}

// DelegatedDerivation extends a Derivation with a derivation from a DS.
type DelegatedDerivation interface {
	Derivation
	DeriveLvl2FromDS(meta drkey.Lvl2Meta, ds drkey.DelegationSecret) (drkey.Lvl2Key, error)
}

// KnownDerivations maps the derivation names to their implementations.
var KnownDerivations = make(map[string]Derivation)

// DeriveLvl1 constructs a new level 1 DRKey.
func DeriveLvl1(meta drkey.Lvl1Meta, sv drkey.SV) (drkey.Lvl1Key, error) {
	mac, err := scrypto.InitMac([]byte(sv.Key))
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	all := make([]byte, addr.IABytes)
	meta.DstIA.Write(all)
	mac.Write(all)
	return drkey.Lvl1Key{
		Lvl1Meta: meta,
		Key:      drkey.DRKey(mac.Sum(nil)),
	}, nil
}
