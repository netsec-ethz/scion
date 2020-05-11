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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Lvl1Rep)(nil)

// Lvl1Rep represents the lvel 1 reply from one CS to another.
type Lvl1Rep struct {
	DstIARaw     addr.IAInt `capnp:"dstIA"`
	EpochBegin   uint32
	EpochEnd     uint32
	Cipher       []byte
	Nonce        []byte
	CertVerDst   scrypto.Version
	TimestampRaw uint32 `capnp:"timestamp"`
}

// DstIA returns the source ISD-AS of the DRKey.
func (c *Lvl1Rep) DstIA() addr.IA {
	return c.DstIARaw.IA()
}

// ProtoId returns the proto ID.
func (c *Lvl1Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey.
func (c *Lvl1Rep) Epoch() drkey.Epoch {
	return drkey.NewEpoch(c.EpochBegin, c.EpochEnd)
}

// Timestamp returns the time when this reply was created.
func (c *Lvl1Rep) Timestamp() time.Time {
	return util.SecsToTime(c.TimestampRaw)
}

func (c *Lvl1Rep) String() string {
	return fmt.Sprintf("Timestamp: %v DstIA: %v EpochBegin: %d EpochEnd: %d CertVerEnc: %d",
		util.TimeToCompact(c.Timestamp()), c.DstIA(), c.EpochBegin, c.EpochEnd, c.CertVerDst)
}
