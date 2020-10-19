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

// TODO(juagargi) the standard derivation (in this file) and delegated one will be just
// functions: won't implement any interface in particular. The way to configure
// a new protocol will look like the SCMP or PISKES protocols: new type with their functions, and
// registration with the correct name. No configuration will be allowed to change this (the
// configuration file will not include any mapping protocol->derivation).

// Standard implements the level 2 drkey derivation from level 1, without DS.
type Standard struct{}

// DeriveLvl2 derives the level 2 DRKey without passing through a delegation secret.
func (p Standard) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	h, err := scrypto.InitMac([]byte(key.Key))
	if err != nil {
		return drkey.Lvl2Key{}, err
	}

	pLen := 0
	// add to buffs in reverse order:
	buffs := [][]byte{}
	switch meta.KeyType {
	case drkey.Host2Host:
		if meta.SrcHost.Size() == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a src host, but it is empty")
		}
		b := meta.SrcHost.Pack()
		buffs = [][]byte{
			b,
			{byte(len(b))},
		}
		pLen += len(b) + 1
		fallthrough
	case drkey.AS2Host:
		if meta.DstHost.Size() == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a dst host, but it is empty")
		}
		b := meta.DstHost.Pack()
		buffs = append(buffs,
			b,
			[]byte{byte(len(b))})
		pLen += len(b) + 1
		fallthrough
	case drkey.AS2AS:
		b := []byte(meta.Protocol)
		buffs = append(buffs,
			[]byte{byte(meta.KeyType)},
			b,
			[]byte{byte(len(b))})
		pLen += len(b) + 2
	default:
		return drkey.Lvl2Key{}, common.NewBasicError("Unknown DRKey type", nil)
	}
	all := make([]byte, pLen)
	pLen = 0
	for i := len(buffs) - 1; i >= 0; i-- {
		copy(all[pLen:], buffs[i])
		pLen += len(buffs[i])
	}
	h.Write(all)
	return drkey.Lvl2Key{
		Lvl2Meta: meta,
		Key:      drkey.DRKey(h.Sum(nil)),
	}, nil
}
