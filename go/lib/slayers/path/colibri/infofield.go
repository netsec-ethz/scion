// Copyright 2020 ETH Zurich
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

package colibri

import (
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/serrors"
)

const LenInfoField int = 24

const LenSuffix = 12

type InfoField struct {
	// C denotes the control plane flag.
	C bool
	// R denotes the reverse flag.
	R bool
	// S denotes the segment flag.
	S bool
	// Ver (4 bits) denotes the reservation version.
	Ver uint8
	// CurrHF denotes the current hop field.
	CurrHF uint8
	// HFCount denotes the total number of hop fields.
	HFCount uint8
	// ResIdSuffix (12 bytes) denotes the reservation ID suffix.
	ResIdSuffix []byte // TODO(juagargi) [12]byte instead, remove Clone() method
	// ExpTick denotes the expiration tick, where one tick corresponds to 4 seconds.
	ExpTick uint32
	// BwCls denotes the bandwidth class of the reservation.
	BwCls uint8
	// Rlx denotes the request latency class of the reservation.
	Rlc uint8
	// OrigPayLen denotes the Original Payload Length.
	OrigPayLen uint16
}

func (inf *InfoField) DecodeFromBytes(b []byte) error {
	if inf == nil {
		return serrors.New("colibri info field must not be nil")
	}
	if len(b) < LenInfoField {
		return serrors.New("raw colibri info field buffer too small")
	}
	flags := uint8(b[0])
	inf.C = (flags & (uint8(1) << 7)) != 0
	inf.R = (flags & (uint8(1) << 6)) != 0
	inf.S = (flags & (uint8(1) << 5)) != 0
	inf.Ver = uint8(b[1]) & 0x0f
	inf.CurrHF = uint8(b[2])
	inf.HFCount = uint8(b[3])
	inf.ResIdSuffix = make([]byte, LenSuffix)
	copy(inf.ResIdSuffix, b[4:16])
	inf.ExpTick = binary.BigEndian.Uint32(b[16:20])
	inf.BwCls = uint8(b[20])
	inf.Rlc = uint8(b[21])
	inf.OrigPayLen = binary.BigEndian.Uint16(b[22:24])
	return nil
}

func (inf *InfoField) SerializeTo(b []byte) error {
	if inf == nil {
		return serrors.New("colibri info field must not be nil")
	}
	if len(b) < LenInfoField {
		return serrors.New("raw colibri info field buffer too small")
	}
	if len(inf.ResIdSuffix) != LenSuffix {
		return serrors.New("colibri ResIdSuffix must be 12 bytes long",
			"is", len(inf.ResIdSuffix))
	}
	var flags uint8
	if inf.C {
		flags += uint8(1) << 7
	}
	if inf.R {
		flags += uint8(1) << 6
	}
	if inf.S {
		flags += uint8(1) << 5
	}
	b[0] = flags
	b[1] = inf.Ver & 0x0f
	b[2] = inf.CurrHF
	b[3] = inf.HFCount
	copy(b[4:16], inf.ResIdSuffix)
	binary.BigEndian.PutUint32(b[16:20], inf.ExpTick)
	b[20] = inf.BwCls
	b[21] = inf.Rlc
	binary.BigEndian.PutUint16(b[22:24], inf.OrigPayLen)
	return nil
}

func (inf *InfoField) Clone() *InfoField {
	c := *inf
	c.ResIdSuffix = make([]byte, len(inf.ResIdSuffix))
	copy(c.ResIdSuffix, inf.ResIdSuffix)
	return &c
}
