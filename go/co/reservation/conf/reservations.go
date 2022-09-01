// Copyright 2020 ETH Zurich, Anapaya Systems
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

package conf

import (
	"encoding/json"
	"io/ioutil"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Reservations struct {
	Rsvs []ReservationEntry `json:"reservation_list"`
}

func ReservationsFromFile(filename string) (*Reservations, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, serrors.WrapStr(
			"error loading reservation list", err, "filename", filename)
	}
	rsvs := &Reservations{}
	err = json.Unmarshal(b, rsvs)
	if err != nil {
		return nil, serrors.WrapStr(
			"error parsing reservation list", err, "filename", filename)
	}
	return rsvs, nil
}

type ReservationEntry struct {
	DstAS         addr.IA              `json:"destination"`
	PathType      reservation.PathType `json:"path_type"`
	PathPredicate string               `json:"path_predicate"`
	MaxSize       reservation.BWCls    `json:"max_size"`
	MinSize       reservation.BWCls    `json:"min_size"`
	SplitCls      reservation.SplitCls `json:"split_cls"`
	EndProps      EndProps             `json:"end_props"`
}

type EndProps reservation.PathEndProps

func (p EndProps) MarshalJSON() ([]byte, error) {
	m := map[string][]string{
		"start": nil,
		"end":   nil,
	}
	if reservation.PathEndProps(p)&reservation.StartLocal != 0 {
		m["start"] = append(m["start"], "L")
	}
	if reservation.PathEndProps(p)&reservation.StartTransfer != 0 {
		m["start"] = append(m["start"], "T")
	}
	if reservation.PathEndProps(p)&reservation.EndLocal != 0 {
		m["end"] = append(m["end"], "L")
	}
	if reservation.PathEndProps(p)&reservation.EndTransfer != 0 {
		m["end"] = append(m["end"], "T")
	}
	return json.Marshal(m)
}

func (pep *EndProps) UnmarshalJSON(b []byte) error {
	var m map[string][]string
	if err := json.Unmarshal(b, &m); err != nil {
		return serrors.WrapStr("cannot parse json to end props", err)
	}
	for k, v := range m {
		var mult int
		switch k {
		case "start":
			mult = 1
		case "end":
			mult = 0
		default:
			return serrors.New("illegal entry in path end props", "key", k)
		}
		for _, p := range v {
			switch p {
			case "L":
				*pep |= (1 << (4 * mult))
			case "T":
				*pep |= (2 << (4 * mult))
			default:
				return serrors.New("illegal entry in path end props", "value", p)
			}
		}
	}
	return nil
}
