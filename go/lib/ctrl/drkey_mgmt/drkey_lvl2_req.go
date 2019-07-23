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

var _ proto.Cerealizable = (*DRKeyLvl2Req)(nil)

type DRKeyHost struct {
	Type addr.HostAddrType // uint8
	Host common.RawBytes
}

// NewDRKeyHost returns a new DRKeyHost from an addr.HostAddr.
func NewDRKeyHost(host addr.HostAddr) *DRKeyHost {
	if host == nil {
		host = addr.HostNone{}
	}
	return &DRKeyHost{
		Type: host.Type(),
		Host: host.Pack(),
	}
}

// ToHostAddr returns the host as a addr.HostAddr.
func (h *DRKeyHost) ToHostAddr() addr.HostAddr {
	host, err := addr.HostFromRaw(h.Host, addr.HostAddrType(h.Type))
	if err != nil {
		panic("Could not convert addr.HostAddr to drkey.DRKeyHost")
	}
	return host
}

// DRKeyLvl2Req represents a level 2 key request from an endhost to a CS.
type DRKeyLvl2Req struct {
	Protocol   string
	ReqType    uint8
	ValTimeRaw uint32     `capnp:"valTime"`
	SrcIARaw   addr.IAInt `capnp:"srcIA"`
	DstIARaw   addr.IAInt `capnp:"dstIA"`
	SrcHost    DRKeyHost
	DstHost    DRKeyHost
	Misc       common.RawBytes
}

// SrcIA returns the source IA (fast path).
func (c *DRKeyLvl2Req) SrcIA() addr.IA {
	return c.SrcIARaw.IA()
}

// DstIA returns the destination IA (slow path).
func (c *DRKeyLvl2Req) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ProtoId returns the proto ID.
func (c *DRKeyLvl2Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Req_TypeID
}

// ValTime returns the validity time of the requested DRkey.
func (c *DRKeyLvl2Req) ValTime() time.Time {
	return util.SecsToTime(c.ValTimeRaw)
}

func (c *DRKeyLvl2Req) String() string {
	return fmt.Sprintf("KeyType: %v Protocol: %s SrcIA: %s DstIA: %s ValTime: %v",
		c.ReqType, c.Protocol, c.SrcIA(), c.DstIA(), util.TimeToString(c.ValTime()))
}
