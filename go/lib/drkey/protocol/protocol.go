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
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/drkey"
)

// Derivation specifies the interface to implement for a derivation method.
type Derivation interface {
	Name() string
	DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error)
}

// KnownDerivations maps the derivation names to their implementations.
var KnownDerivations = make(map[string]Derivation)

// Map maps the name of the protocol to the derivation the protocol uses. Many different protocols
// can use the same derivation.
type Map struct {
	m sync.Map
}

// Register registers a protocol with a derivation.
func (m *Map) Register(protocolName string, derivationName string) error {
	proto, found := KnownDerivations[derivationName]
	if !found {
		return fmt.Errorf("There is no DRKey derivation with name \"%s\"", derivationName)
	}
	m.m.Store(protocolName, proto)
	return nil
}

// Find returns the derivation associated with a protocol.
func (m *Map) Find(name string) Derivation {
	p, _ := m.m.Load(name)
	if p == nil {
		return nil
	}
	return p.(Derivation)
}

// DeriveLvl2 will find the derivation associated with the key's protocol and use it to
// derive the level 2 drkey.
func (m *Map) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	p := m.Find(meta.Protocol)
	if p == nil {
		return drkey.Lvl2Key{},
			fmt.Errorf("Cannot find derivation for protocol %s", meta.Protocol)
	}
	return p.DeriveLvl2(meta, key)
}
