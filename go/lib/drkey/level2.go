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
	"errors"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Lvl2KeyType represents the different types of level 2 DRKeys (AS->AS, AS->host, host->host)
type Lvl2KeyType uint8

const (
	AS2AS Lvl2KeyType = iota
	AS2Host
	Host2Host
)

// Lvl2Meta represents the information about a level 2 DRKey, without the key itself
type Lvl2Meta struct {
	KeyType  Lvl2KeyType
	Protocol string
	Epoch    Epoch
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  addr.HostAddr
	DstHost  addr.HostAddr
}

func (k *Lvl2Meta) String() string {
	return fmt.Sprintf("%v %v %v %v %v %v %v", k.KeyType, k.Protocol, k.Epoch, k.SrcIA, k.DstIA, k.SrcHost, k.DstHost)
}

// Lvl2Key represents a level 2 DRKey
type Lvl2Key struct {
	Lvl2Meta
	DRKey
}

func (k *Lvl2Key) String() string {
	return fmt.Sprintf("%v %v", k.Lvl2Meta, k.DRKey)
}

// NewLvl2Key constructs a level 2 DRKey
func NewLvl2Key(meta Lvl2Meta, lvl1 Lvl1Key) (Lvl2Key, error) {
	h, err := scrypto.InitMac(lvl1.DRKey.Key)
	if err != nil {
		return Lvl2Key{}, err
	}

	pLen := 1
	buffs := []common.RawBytes{}
	switch meta.KeyType {
	case Host2Host:
		if meta.SrcHost.Size() == 0 {
			return Lvl2Key{}, errors.New("Level 2 DRKey requires a src host, but it is empty")
		}
		b := meta.SrcHost.Pack()
		buffs = []common.RawBytes{b}
		pLen += len(b)
		fallthrough
	case AS2Host:
		if meta.DstHost.Size() == 0 {
			return Lvl2Key{}, errors.New("Level 2 DRKey requires a dst host, but it is empty")
		}
		b := meta.DstHost.Pack()
		buffs = append(buffs, b)
		pLen += len(b)
		fallthrough
	case AS2AS:
		b := common.RawBytes(meta.Protocol)
		buffs = append(buffs, b)
		pLen += len(b)
	default:
		return Lvl2Key{}, common.NewBasicError("Unknown DRKey type", nil)
	}
	all := make(common.RawBytes, pLen)
	copy(all[:1], common.RawBytes{byte(pLen)})
	pLen = 1
	for i := len(buffs) - 1; i >= 0; i-- {
		copy(all[pLen:], buffs[i])
		pLen += len(buffs[i])
	}
	return Lvl2Key{
		Lvl2Meta: meta,
		DRKey:    DRKey{h.Sum(all)},
	}, nil
}
