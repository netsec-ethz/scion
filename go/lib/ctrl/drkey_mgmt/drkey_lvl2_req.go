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
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Lvl2Req)(nil)

// Host represents a host part of a level 2 drkey.
type Host struct {
	Type addr.HostAddrType // uint8
	Host []byte
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
	Misc       []byte
}

// NewLvl2ReqFromMeta constructs a level 2 request from a standard level 2 meta info.
func NewLvl2ReqFromMeta(meta drkey.Lvl2Meta, valTime time.Time) Lvl2Req {
	return Lvl2Req{
		ReqType:    uint8(meta.KeyType),
		Protocol:   meta.Protocol,
		ValTimeRaw: util.TimeToSecs(valTime),
		SrcIARaw:   meta.SrcIA.IAInt(),
		DstIARaw:   meta.DstIA.IAInt(),
		SrcHost:    NewHost(meta.SrcHost),
		DstHost:    NewHost(meta.DstHost),
	}
}

// ProtoId returns the proto ID.
func (c *Lvl2Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Req_TypeID
}

// SrcIA returns the source IA (fast path).
func (c *Lvl2Req) SrcIA() addr.IA {
	return c.SrcIARaw.IA()
}

// DstIA returns the destination IA (slow path).
func (c *Lvl2Req) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ValTime returns the validity time of the requested DRKey.
func (c *Lvl2Req) ValTime() time.Time {
	return util.SecsToTime(c.ValTimeRaw)
}

// ToMeta returns metadata of the requested Lvl2 DRKey.
func (c *Lvl2Req) ToMeta() drkey.Lvl2Meta {
	return drkey.Lvl2Meta{
		KeyType:  drkey.Lvl2KeyType(c.ReqType),
		Protocol: c.Protocol,
		SrcIA:    c.SrcIA(),
		DstIA:    c.DstIA(),
		SrcHost:  c.SrcHost.ToHostAddr(),
		DstHost:  c.DstHost.ToHostAddr(),
	}
}

func (c *Lvl2Req) String() string {
	return fmt.Sprintf("KeyType: %v Protocol: %s SrcIA: %s DstIA: %s ValTime: %v",
		c.ReqType, c.Protocol, c.SrcIA(), c.DstIA(), util.TimeToCompact(c.ValTime()))
}
