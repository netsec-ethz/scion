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

// This file contains the Go representation of first order DRKey responses.

package drkey_mgmt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyLvl2Rep)(nil)

type DRKeyLvl2Rep struct {
	Timestamp  uint32
	Drkey      common.RawBytes
	EpochBegin uint32
	EpochEnd   uint32
	Misc       common.RawBytes
}

func (c *DRKeyLvl2Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey
func (c *DRKeyLvl2Rep) Epoch() *drkey.Epoch {
	return &drkey.Epoch{Begin: c.EpochBegin, End: c.EpochEnd}
}

func (c *DRKeyLvl2Rep) String() string {
	return fmt.Sprintf("Timestamp: %d EpochBegin: %d EpochEnd: %d Misc: %v",
		c.Timestamp, c.EpochBegin, c.EpochEnd, c.Misc)
}
