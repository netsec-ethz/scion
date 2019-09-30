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
}

type registry map[string]Derivation

// NewRegistry creates and initializes a new Registry with the default registrations.
func NewRegistry() Registry {
	r := registry{}
	for k, v := range defaultRegistrations {
		r[k] = v
	}
	return &r
}

// Register registers a protocol with a derivation.
func (r registry) Register(protocolName string, derivationName string) error {
	der := KnownDerivations[derivationName]
	if der == nil {
		return fmt.Errorf("There is no DRKey derivation with name \"%s\"", derivationName)
	}
	r[protocolName] = der
	return nil
}

// Find returns the derivation associated with a protocol.
func (r registry) Find(name string) Derivation {
	return r[name]
}
