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
	"reflect"
	"sync"

	"github.com/scionproto/scion/go/lib/drkey"
)

// defaultRegistrations is the map of the already present protocol derivations.
var defaultRegistrations = map[string]Derivation{
	scmp{}.Name():   scmp{},
	piskes{}.Name(): piskes{},
}

// Registry maps the name of the protocol to the derivation the protocol uses.
// Many different protocols can use the same derivation.
type Registry interface {
	Register(protocolName, derivationName string) error
	Find(name string) Derivation
	DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error)
}

type registry struct {
	// m is a sync Map between the protocol name and the Derivation.
	m sync.Map
}

// NewRegistry creates and initializes a new Registry with the default registrations.
func NewRegistry() Registry {
	r := &registry{}
	for k, v := range defaultRegistrations {
		r.m.Store(k, v)
	}
	return r
}

// Register registers a protocol with a derivation.
func (r *registry) Register(protocolName string, derivationName string) error {
	der, found := KnownDerivations[derivationName]
	if !found {
		return fmt.Errorf("There is no DRKey derivation with name \"%s\"", derivationName)
	}
	// check if this protocol was already registered to a different derivation
	if p := r.Find(protocolName); p != nil && reflect.TypeOf(p) != reflect.TypeOf(der) {
		return fmt.Errorf("Protocol \"%s\" already register to \"%s\" [\"%s\" in registry]\n"+
			"Existing: %T(%p) ; New: %T(%p)",
			protocolName, der.Name(), p.Name(),
			p, p, der, der)
	}
	r.m.Store(protocolName, der)
	return nil
}

// Find returns the derivation associated with a protocol.
func (r *registry) Find(name string) Derivation {
	p, _ := r.m.Load(name)
	if p == nil {
		return nil
	}
	return p.(Derivation)
}

// DeriveLvl2 will find the derivation associated with the key's protocol and use it to
// derive the level 2 drkey.
func (r *registry) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	p := r.Find(meta.Protocol)
	if p == nil {
		return drkey.Lvl2Key{},
			fmt.Errorf("Cannot find derivation for protocol %s", meta.Protocol)
	}
	return p.DeriveLvl2(meta, key)
}
