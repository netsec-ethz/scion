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
	"sync/atomic"

	"github.com/scionproto/scion/go/lib/drkey"
)

// Protocol specifies the interface to implement for protocols with their own derivation method.
type Protocol interface {
	Name() string
	DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error)
}

// KnownImplementations maps the protocol names to their implementations
var KnownImplementations = make(map[string]Protocol)

// Map maps the name of the protocol to the implementation. It also contains a possible
// default implementation.
type Map struct {
	m               sync.Map
	defaultProtocol atomic.Value
}

// RegisterDefaultImplementation will set the default protocol.
func (m *Map) RegisterDefaultImplementation(implementationName string) error {
	defaultProtocol, found := KnownImplementations[implementationName]
	if !found {
		return fmt.Errorf("There is no DRKey implementation with name \"%s\"", implementationName)
	}
	m.defaultProtocol.Store(defaultProtocol)
	return nil
}

// DefaultProtocol returns the default protocol.
func (m *Map) DefaultProtocol() Protocol {
	return protoOrNil(m.defaultProtocol.Load())
}

// Register registers a protocol given its name and implementation.
func (m *Map) Register(protocolName string, implementationName string) error {
	proto, found := KnownImplementations[implementationName]
	if !found {
		return fmt.Errorf("There is no DRKey implementation with name \"%s\"", implementationName)
	}
	m.m.Store(protocolName, proto)
	return nil
}

// Find returns the implementation associated with a protocol.
func (m *Map) Find(name string) Protocol {
	p, _ := m.m.Load(name)
	return protoOrNil(p)
}

// FindOrDefault will return the protocol with that name if found, or the default one if not.
func (m *Map) FindOrDefault(name string) Protocol {
	raw, found := m.m.Load(name)
	p := protoOrNil(raw)
	if !found {
		p = m.DefaultProtocol()
	}
	return p
}

// DeriveLvl2 will find the implementation associated with the key's protocol and use it to
// derive the level 2 drkey.
func (m *Map) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	p := m.FindOrDefault(meta.Protocol)
	if p == nil {
		return drkey.Lvl2Key{},
			fmt.Errorf("Cannot find implementation for protocol %s", meta.Protocol)
	}
	return p.DeriveLvl2(meta, key)
}

func protoOrNil(raw interface{}) Protocol {
	if raw != nil {
		return raw.(Protocol)
	}
	return nil
}
