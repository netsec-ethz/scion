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
	"errors"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// StandardName is the name of the DRKey standard derivation algorithm.
const StandardName = "standard"

// StandardImpl is the standard implementation of the level 2 drkey derivation, i.e. directly
// from level 1 derivation without DS.
var standardImpl = Standard{}

// Standard implements the level 2 drkey derivation from level 1, without DS.
type Standard struct {
}

// Name of this protocol
func (p Standard) Name() string {
	return StandardName
}

// DeriveLvl2 derives the level 2 DRKey without passing through a delegation secret.
func (p Standard) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	h, err := scrypto.InitMac(common.RawBytes(key.Key))
	if err != nil {
		return drkey.Lvl2Key{}, err
	}

	pLen := 0
	buffs := []common.RawBytes{}
	switch meta.KeyType {
	case drkey.Host2Host:
		if meta.SrcHost.Size() == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a src host, but it is empty")
		}
		b := meta.SrcHost.Pack()
		buffs = []common.RawBytes{b}
		pLen += len(b)
		fallthrough
	case drkey.AS2Host:
		if meta.DstHost.Size() == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a dst host, but it is empty")
		}
		b := meta.DstHost.Pack()
		buffs = append(buffs, b)
		pLen += len(b)
		fallthrough
	case drkey.AS2AS:
		b := common.RawBytes(meta.Protocol)
		buffs = append(buffs, b)
		pLen += len(b)
	default:
		return drkey.Lvl2Key{}, common.NewBasicError("Unknown DRKey type", nil)
	}
	all := make(common.RawBytes, pLen+1)
	copy(all[:1], common.RawBytes{byte(pLen)})
	pLen = 1
	for i := len(buffs) - 1; i >= 0; i-- {
		copy(all[pLen:], buffs[i])
		pLen += len(buffs[i])
	}
	return drkey.Lvl2Key{
		Lvl2Meta: meta,
		Key:      drkey.DRKey(h.Sum(all)),
	}, nil
}

func init() {
	KnownDerivations[standardImpl.Name()] = &standardImpl
}
