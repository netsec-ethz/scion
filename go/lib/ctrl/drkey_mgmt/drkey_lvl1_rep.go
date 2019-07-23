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

// DRKeyLvl1Rep represents the lvel 1 reply from one CS to another.
type DRKeyLvl1Rep struct {
	DstIARaw   addr.IAInt `capnp:"dstIA"`
	EpochBegin uint32
	EpochEnd   uint32
	Cipher     common.RawBytes
	Nonce      common.RawBytes
	CertVerDst uint64
}

// DstIA returns the source ISD-AS of the DRKey.
func (c *DRKeyLvl1Rep) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ProtoId returns the proto ID.
func (c *DRKeyLvl1Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey.
func (c *DRKeyLvl1Rep) Epoch() drkey.Epoch {
	return drkey.NewEpoch(c.EpochBegin, c.EpochEnd)
}

func (c *DRKeyLvl1Rep) String() string {
	return fmt.Sprintf("DstIA: %v EpochBegin: %d EpochEnd: %d CertVerEnc: %d",
		c.DstIA(), c.EpochBegin, c.EpochEnd, c.CertVerDst)
}
