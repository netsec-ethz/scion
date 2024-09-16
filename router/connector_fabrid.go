// Copyright 2024 ETH Zurich
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

package router

import "github.com/scionproto/scion/router/control"

func (c *Connector) AddDRKeySecret(protocolID int32, sv control.SecretValue) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.DataPlane.DRKeyProvider.AddSecret(protocolID, sv)
}

func (c *Connector) UpdateFabridPolicies(ipRangePolicies map[uint32][]*control.PolicyIPRange,
	interfacePolicies map[uint64]uint32) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.DataPlane.UpdateFabridPolicies(ipRangePolicies, interfacePolicies)
}
