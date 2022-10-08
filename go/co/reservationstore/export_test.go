// Copyright 2021 ETH Zurich, Anapaya Systems
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

package reservationstore

import (
	"github.com/scionproto/scion/go/lib/addr"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

func (s *Store) ComputeMAC(suffix []byte, tok *reservation.Token, srcAS, dstAS addr.AS,
	ingress, egress uint16) error {
	return s.addHopFieldToColibriPath(suffix, tok, srcAS, dstAS, ingress, egress)
}

func (s *Store) SetColibriKey(key []byte) {
	colibriKey, _ := libcolibri.InitColibriKey(key)
	s.colibriKey = colibriKey
}
