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

// DelegatedName is the name of the level 2 derivation using a delegation secret.
const DelegatedName = "delegated"

// DelegatedImpl is the standard implementation of the level 2 drkey derivation, i.e. directly
// from level 1 derivation without DS.
var delegatedImpl = Delegated{}

// Delegated implements the level 2 drkey derivation from level 1, without DS.
type Delegated struct {
}

// Name of this protocol
func (p Delegated) Name() string {
	return DelegatedName
}

// DeriveLvl2 derives the level 2 DRKey without passing through a delegation secret.
func (p Delegated) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	metaForDS := meta
	meta.KeyType = drkey.AS2AS
	ds, err := standardImpl.DeriveLvl2(metaForDS, key)
	if err != nil {
		return drkey.Lvl2Key{}, common.NewBasicError("Error deriving DS", err)
	}
	h, err := scrypto.InitMac(common.RawBytes(ds.Key))
	if err != nil {
		return drkey.Lvl2Key{}, err
	}

	pLen := 1
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
	all := make(common.RawBytes, pLen)
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
	KnownImplementations[delegatedImpl.Name()] = &delegatedImpl
}
