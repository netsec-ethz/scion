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

const LenHopField int = 8

type HopField struct {
	// IngressId denotes the ingress interface in the direction of the reservation (R=0).
	IngressId uint16
	// EgressId denotes the egress interface in the direction of the reservation (R=0).
	EgressId uint16
	// Mac (4 bytes) denotes the MAC (static or per-packet MAC, depending on the S flag).
	Mac []byte // TODO(juagargi) this ought to be [4]byte instead, remove Clone() method
}

func (hf *HopField) DecodeFromBytes(b []byte) error {
	if hf == nil {
		return serrors.New("colibri hop field must not be nil")
	}
	if len(b) < LenHopField {
		return serrors.New("raw colibri hop field buffer too small")
	}
	hf.IngressId = binary.BigEndian.Uint16(b[:2])
	hf.EgressId = binary.BigEndian.Uint16(b[2:4])
	hf.Mac = make([]byte, 4)
	copy(hf.Mac, b[4:8])
	return nil
}

func (hf *HopField) SerializeTo(b []byte) error {
	if hf == nil {
		return serrors.New("colibri hop field must not be nil")
	}
	if len(b) < LenHopField {
		return serrors.New("raw colibri hop field buffer too small")
	}
	if len(hf.Mac) != 4 {
		return serrors.New("colibri mac must be 4 bytes long", "is", len(hf.Mac))
	}
	binary.BigEndian.PutUint16(b[:2], hf.IngressId)
	binary.BigEndian.PutUint16(b[2:4], hf.EgressId)
	copy(b[4:8], hf.Mac)
	return nil
}

func (hf *HopField) Clone() *HopField {
	c := &HopField{
		IngressId: hf.IngressId,
		EgressId:  hf.EgressId,
		Mac:       make([]byte, 4),
	}
	copy(c.Mac, hf.Mac)
	return c
}

func (hf *HopField) SwapInEg() {
	hf.IngressId, hf.EgressId = hf.EgressId, hf.IngressId
}
