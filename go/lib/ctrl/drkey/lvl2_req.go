// Copyright 2020 ETH Zurich
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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
)

// Host represents a host part of a level 2 drkey.
type Host struct {
	Type addr.HostAddrType // uint8
	Host []byte
}

// ToHostAddr returns the host as a addr.HostAddr.
func (h *Host) ToHostAddr() addr.HostAddr {
	host, err := addr.HostFromRaw(h.Host, addr.HostAddrType(h.Type))
	if err != nil {
		panic("Could not convert addr.HostAddr to drkey.Host")
	}
	return host
}

// Lvl2Req represents a level 2 key request from an endhost to a CS.
type Lvl2Req struct {
	Protocol string
	ReqType  uint32
	ValTime  time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  Host
	DstHost  Host
	Misc     []byte
}
