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
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Lvl1Req)(nil)

// Lvl1Req represents a level 1 request between certificate servers.
type Lvl1Req struct {
	DstIARaw     addr.IAInt `capnp:"dstIA"`
	ValTimeRaw   uint32     `capnp:"valTime"`
	TimestampRaw uint32     `capnp:"timestamp"`
}

// NewLvl1Req creates a new level 1 request struct.
func NewLvl1Req(dstIA addr.IA, valTime uint32) Lvl1Req {
	return Lvl1Req{
		DstIARaw:     dstIA.IAInt(),
		ValTimeRaw:   valTime,
		TimestampRaw: uint32(time.Now().Unix()),
	}
}

// DstIA returns the source ISD-AS of the requested DRKey.
func (c *Lvl1Req) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ProtoId returns the proto ID
func (c *Lvl1Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Req_TypeID
}

// ValTime returns the validity time of the requested DRKey.
func (c *Lvl1Req) ValTime() time.Time {
	return util.SecsToTime(c.ValTimeRaw)
}

// Timestamp returns the time when this request was created.
func (c *Lvl1Req) Timestamp() time.Time {
	return util.SecsToTime(c.TimestampRaw)
}

func (c *Lvl1Req) String() string {
	return fmt.Sprintf("Timestamp: %v DstIA: %s ValTime: %v",
		util.TimeToCompact(c.Timestamp()), c.DstIA(), util.TimeToCompact(c.ValTime()))
}
