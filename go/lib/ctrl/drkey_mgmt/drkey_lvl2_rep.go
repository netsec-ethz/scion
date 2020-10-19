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

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Lvl2Rep)(nil)

// Lvl2Rep encodes the level 2 key response from a CS to an endhost.
type Lvl2Rep struct {
	TimestampRaw uint32 `capnp:"timestamp"`
	DRKeyRaw     []byte `capnp:"drkey"`
	EpochBegin   uint32
	EpochEnd     uint32
	Misc         []byte
}

// NewLvl2RepFromKey constructs a level 2 response from a standard level 2 key.
func NewLvl2RepFromKey(key drkey.Lvl2Key, timestamp time.Time) *Lvl2Rep {
	return &Lvl2Rep{
		TimestampRaw: util.TimeToSecs(timestamp),
		DRKeyRaw:     []byte(key.Key),
		EpochBegin:   util.TimeToSecs(key.Epoch.NotBefore),
		EpochEnd:     util.TimeToSecs(key.Epoch.NotAfter),
	}
}

// ProtoId returns the proto ID.
func (c *Lvl2Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl2Rep_TypeID
}

// Epoch returns the begin and end of the validity period of DRKey.
func (c *Lvl2Rep) Epoch() drkey.Epoch {
	return drkey.NewEpoch(c.EpochBegin, c.EpochEnd)
}

// ToKey returns a drkey Lvl2 built from these values.
func (c *Lvl2Rep) ToKey(meta drkey.Lvl2Meta) drkey.Lvl2Key {

	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			Epoch:    c.Epoch(),
			SrcIA:    meta.SrcIA,
			DstIA:    meta.DstIA,
			KeyType:  meta.KeyType,
			Protocol: meta.Protocol,
			SrcHost:  meta.SrcHost,
			DstHost:  meta.DstHost,
		},
		Key: drkey.DRKey(c.DRKeyRaw),
	}
}

// Timestamp returns the time when this reply was created.
func (c *Lvl2Rep) Timestamp() time.Time {
	return util.SecsToTime(c.TimestampRaw)
}

func (c *Lvl2Rep) String() string {
	return fmt.Sprintf("Timestamp: %v EpochBegin: %d EpochEnd: %d Misc: %v",
		util.TimeToCompact(c.Timestamp()), c.EpochBegin, c.EpochEnd, c.Misc)
}
