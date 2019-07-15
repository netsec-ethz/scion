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

var _ proto.Cerealizable = (*DRKeyLvl1Req)(nil)

// DRKeyLvl1Req represents a level 1 request between certificate servers
type DRKeyLvl1Req struct {
	// TODO drkeytest: why src IA instead of dst IA ?
	// SrcIa     addr.IAInt
	DstIa     addr.IAInt
	ValTime   uint32
	Timestamp uint32
}

// NewDRKeyLvl1Req creates a new L1 request struct
func NewDRKeyLvl1Req(dstIA addr.IA, valTime uint32) *DRKeyLvl1Req {
	return &DRKeyLvl1Req{
		DstIa:     dstIA.IAInt(),
		ValTime:   valTime,
		Timestamp: uint32(time.Now().Unix()),
	}
}

// DstIA returns the source ISD-AS of the requested DRKey
func (c *DRKeyLvl1Req) DstIA() addr.IA {
	return c.DstIa.IA()
}

// ProtoId returns the proto ID
func (c *DRKeyLvl1Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Req_TypeID
}

// Time returns the validity time of the requested DRKey
func (c *DRKeyLvl1Req) Time() time.Time {
	return util.SecsToTime(c.ValTime)
}

// WhenCreated returns the time when this request was created
func (c *DRKeyLvl1Req) WhenCreated() time.Time {
	return util.SecsToTime(c.Timestamp)
}

func (c *DRKeyLvl1Req) String() string {
	return fmt.Sprintf("DstIA: %s ValTime: %v", c.DstIA(), util.TimeToString(c.Time()))
}
