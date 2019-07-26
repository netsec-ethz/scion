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

var _ proto.Cerealizable = (*DRKeyLvl2Rep)(nil)

// DRKeyLvl2Rep encodes the level 2 key response from a CS to an endhost.
type DRKeyLvl2Rep struct {
	TimestampRaw uint32          `capnp:"timestamp"`
	DRKeyRaw     common.RawBytes `capnp:"drkey"`
	EpochBegin   uint32
	EpochEnd     uint32
	Misc         common.RawBytes
}

// NewDRKeyLvl2RepFromKeyRepresentation constructs a level 2 response from a standard level 2 key.
func NewDRKeyLvl2RepFromKeyRepresentation(key drkey.Lvl2Key, timestamp uint32) DRKeyLvl2Rep {
	return DRKeyLvl2Rep{
		TimestampRaw: timestamp,
		DRKeyRaw:     key.Key,
		EpochBegin:   key.Epoch.BeginAsSeconds(),
		EpochEnd:     key.Epoch.EndAsSeconds(),
	}
}

// ProtoId returns the proto ID.
func (c *DRKeyLvl2Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey.
func (c *DRKeyLvl2Rep) Epoch() drkey.Epoch {
	return drkey.NewEpoch(c.EpochBegin, c.EpochEnd)
}

// ToKeyRepresentation returns a drkey Lvl2 built from these values.
func (c *DRKeyLvl2Rep) ToKeyRepresentation(srcIA, dstIA addr.IA, keyType drkey.Lvl2KeyType,
	protocol string, srcHost, dstHost addr.HostAddr) drkey.Lvl2Key {

	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			Epoch:    drkey.NewEpoch(c.EpochBegin, c.EpochEnd),
			SrcIA:    srcIA,
			DstIA:    dstIA,
			KeyType:  keyType,
			Protocol: protocol,
			SrcHost:  srcHost,
			DstHost:  dstHost,
		},
		DRKey: drkey.DRKey{Key: c.DRKeyRaw},
	}
}

func (c *DRKeyLvl2Rep) String() string {
	return fmt.Sprintf("Timestamp: %d EpochBegin: %d EpochEnd: %d Misc: %v",
		c.TimestampRaw, c.EpochBegin, c.EpochEnd, c.Misc)
}
