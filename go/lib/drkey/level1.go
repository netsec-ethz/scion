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
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Lvl1Meta represents the information about a level 1 DRKey other than the key itself.
type Lvl1Meta struct {
	Epoch Epoch
	SrcIA addr.IA
	DstIA addr.IA
}

// Lvl1Key represents a level 1 DRKey.
type Lvl1Key struct {
	Lvl1Meta
	DRKey
}

func (k Lvl1Key) String() string {
	return fmt.Sprintf("%+v %+v", k.Lvl1Meta, k.DRKey)
}

// DeriveLvl1 constructs a new level 1 DRKey.
func DeriveLvl1(meta Lvl1Meta, sv SV) (Lvl1Key, error) {
	mac, err := scrypto.InitMac(sv.DRKey.RawBytes)
	if err != nil {
		return Lvl1Key{}, err
	}
	all := make(common.RawBytes, addr.IABytes)
	meta.DstIA.Write(all)
	mac.Write(all)
	tmp := make([]byte, 0, mac.Size())
	return Lvl1Key{
		Lvl1Meta: meta,
		DRKey:    DRKey{mac.Sum(tmp)},
	}, nil
}
