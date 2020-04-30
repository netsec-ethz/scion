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

// Lvl2KeyType represents the different types of level 2 DRKeys (AS->AS, AS->host, host->host).
type Lvl2KeyType uint8

// Lvl2KeyType constants
const (
	AS2AS Lvl2KeyType = iota
	AS2Host
	Host2Host
)

// Lvl2Meta represents the information about a level 2 DRKey, without the key itself.
type Lvl2Meta struct {
	KeyType  Lvl2KeyType
	Protocol string
	Epoch    Epoch
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  addr.HostAddr
	DstHost  addr.HostAddr
}

// Equal returns true if both meta are identical.
func (m Lvl2Meta) Equal(other Lvl2Meta) bool {
	return m.KeyType == other.KeyType && m.Protocol == other.Protocol &&
		m.Epoch.Equal(other.Epoch) && m.SrcIA.Equal(other.SrcIA) && m.DstIA.Equal(other.DstIA) &&
		m.SrcHost.Equal(other.SrcHost) && m.DstHost.Equal(other.DstHost)
}

// Lvl2Key represents a level 2 DRKey.
type Lvl2Key struct {
	Lvl2Meta
	Key DRKey
}

// Equal returns true if both level 2 keys are identical.
func (k Lvl2Key) Equal(other Lvl2Key) bool {
	return k.Lvl2Meta.Equal(other.Lvl2Meta) && bytes.Compare(k.Key, other.Key) == 0
}

// DelegationSecret is similar to a level 2 key, type AS to AS.
type DelegationSecret struct {
	Protocol string
	Epoch    Epoch
	SrcIA    addr.IA
	DstIA    addr.IA
	Key      DRKey
}
