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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyLvl1Rep)(nil)

type DRKeyLvl1Rep struct {
	SrcIa      addr.IAInt
	EpochBegin uint32
	EpochEnd   uint32
	Cipher     common.RawBytes
	CertVerDst uint64
}

// IA returns the source ISD-AS of the DRKey
func (c *DRKeyLvl1Rep) IA() addr.IA {
	return c.SrcIa.IA()
}

func (c *DRKeyLvl1Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey
func (c *DRKeyLvl1Rep) Epoch() *drkey.Epoch {
	return &drkey.Epoch{Begin: c.EpochBegin, End: c.EpochEnd}
}

func (c *DRKeyLvl1Rep) String() string {
	return fmt.Sprintf("SrcIA: %v EpochBegin: %d EpochEnd: %d CertVerEnc: %d",
		c.IA(), c.EpochBegin, c.EpochEnd, c.CertVerDst)
}
