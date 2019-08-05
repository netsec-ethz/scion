// Copyright 2018 ETH Zurich
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

// This file contains the Go representation of first order DRKey requests.

package drkey_mgmt

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Lvl2Req)(nil)

// Host represents a host part of a level 2 drkey.
type Host struct {
	Type addr.HostAddrType // uint8
	Host common.RawBytes
}

// NewHost returns a new Host from an addr.HostAddr.
func NewHost(host addr.HostAddr) Host {
	if host == nil {
		host = addr.HostNone{}
	}
	return Host{
		Type: host.Type(),
		Host: host.Pack(),
	}
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
	Protocol   string
	ReqType    uint8
	ValTimeRaw uint32     `capnp:"valTime"`
	SrcIARaw   addr.IAInt `capnp:"srcIA"`
	DstIARaw   addr.IAInt `capnp:"dstIA"`
	SrcHost    Host
	DstHost    Host
	Misc       common.RawBytes
}

// SrcIA returns the source IA (fast path).
func (c *Lvl2Req) SrcIA() addr.IA {
	return c.SrcIARaw.IA()
}

// DstIA returns the destination IA (slow path).
func (c *Lvl2Req) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ProtoId returns the proto ID.
func (c *Lvl2Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Req_TypeID
}

// ValTime returns the validity time of the requested DRKey.
func (c *Lvl2Req) ValTime() time.Time {
	return util.SecsToTime(c.ValTimeRaw)
}

func (c *Lvl2Req) String() string {
	return fmt.Sprintf("KeyType: %v Protocol: %s SrcIA: %s DstIA: %s ValTime: %v",
		c.ReqType, c.Protocol, c.SrcIA(), c.DstIA(), util.TimeToCompact(c.ValTime()))
}
