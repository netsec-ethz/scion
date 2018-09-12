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

	"github.com/scionproto/scion/go/lib/common"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyLvl2Req)(nil)

type DRKeyLvl2Req struct {
	Protocol string
	ReqType  uint8
	ValTime  uint32
	SrcIa    addr.IAInt
	DstIa    addr.IAInt
	SrcHost  addr.HostAddr
	DstHost  addr.HostAddr
	Misc     common.RawBytes
}

func (c *DRKeyLvl2Req) IA() addr.IA {
	return c.SrcIa.IA()
}

func (c *DRKeyLvl2Req) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Req_TypeID
}

// Time returns the validity time of the requested DRkey
func (c *DRKeyLvl2Req) Time() time.Time {
	return util.SecsToTime(c.ValTime)
}

func (c *DRKeyLvl2Req) String() string {
	return fmt.Sprintf("SrcIA: %s ValTime: %v", c.IA(), util.TimeToString(c.Time()))
}
