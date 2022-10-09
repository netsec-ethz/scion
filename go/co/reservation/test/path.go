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

package test

import (
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/common"
	slayers "github.com/scionproto/scion/go/lib/slayers/path"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
)

// NewSteps creates a base.PathSteps. Use: NewSteps(0,"1-ffaa:0:1", 1, 2, "1-ffaa:0:2", 0)
// Or omit the starting and ending 0-interfaces: NewSteps("1-ffaa:0:1", 1, 2, "1-ffaa:0:2")
func NewSteps(chain ...interface{}) base.PathSteps {
	switch {
	case len(chain)%3 == 1:
		chain = append([]interface{}{0}, append(chain, 0)...)
	case len(chain)%3 != 0:
		panic("wrong number of arguments")
	}

	steps := make(base.PathSteps, 0)
	for i := 0; i < len(chain); i += 3 {
		steps = append(steps, base.PathStep{
			Ingress: uint16(chain[i].(int)),
			Egress:  uint16(chain[i+2].(int)),
			IA:      xtest.MustParseIA(chain[i+1].(string)),
		})
	}
	return steps
}

// NewSnetPath builds a valid snet Path (a path.Path with a SCION raw dataplane path inside).
// NewSnetPath is called like
// NewSnetPath("1-ff00:0:1", 1,  2, "1-ff00:1:2", 3,     4, "1-ff00:0:3"))
func NewSnetPath(args ...interface{}) snet.Path {
	ifaces := newIfaces(args...)
	steps, err := base.StepsFromInterfaces(ifaces)
	if err != nil {
		panic(err)
	}

	rp := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{uint8(len(steps))},
			},
			NumINF:  1,
			NumHops: len(steps),
		},
		InfoFields: []slayers.InfoField{{
			ConsDir: true,
		}},
		HopFields: make([]slayers.HopField, len(steps)),
	}
	for i, iface := range steps {
		rp.HopFields[i] = slayers.HopField{
			ConsIngress: iface.Ingress,
			ConsEgress:  iface.Egress,
		}
	}
	// to raw
	buff := make([]byte, rp.Len())
	err = rp.SerializeTo(buff)
	if err != nil {
		panic(err)
	}
	// finally the snet path with a dataplane path of SCION type
	return path.Path{
		Meta: snet.PathMetadata{
			Interfaces: ifaces,
		},
		DataplanePath: path.SCION{
			Raw: buff,
		},
	}
}

// NewColPath builds a partial colibri path from provided steps.
// Some fields are not populated: every MAC of every hop field is empty, as well as
// the high precision timestamp, and Index,CurrHF,Suffix,ExpTick,BwCls,Rlc, and OrigPayLen.
func NewColPath(steps base.PathSteps) *colpath.ColibriPath {
	colPath := &colpath.ColibriPath{
		InfoField: &colpath.InfoField{
			ResIdSuffix: make([]byte, 12),
			S:           true,
			C:           true,
			HFCount:     uint8(len(steps)),
		},
		HopFields: make([]*colpath.HopField, len(steps)),
	}
	for i, s := range steps {
		colPath.HopFields[i] = &colpath.HopField{
			IngressId: s.Ingress,
			EgressId:  s.Egress,
			Mac:       make([]byte, 4),
		}
	}
	return colPath
}

// NewColPathMin builds a partial colibri minimal path from provided steps.
// Some fields are not populated: every MAC of every hop field is empty, as well as
// the high precision timestamp, and Index,CurrHF,Suffix,ExpTick,BwCls,Rlc, and OrigPayLen.
func NewColPathMin(steps base.PathSteps) *colpath.ColibriPathMinimal {
	c := NewColPath(steps)
	buff := make([]byte, (c.Len()))
	if err := c.SerializeTo(buff); err != nil {
		panic(err)
	}
	m := &colpath.ColibriPathMinimal{}
	if err := m.DecodeFromBytes(buff); err != nil {
		panic(err)
	}
	return m
}

// newIfaces("1-ff00:0:1",1,   2, "1-ff00:1:2", 3,   4, "1-ff00:0:3") .
func newIfaces(args ...interface{}) []snet.PathInterface {
	if len(args) == 0 {
		return []snet.PathInterface{}
	}
	if (len(args)+2)%3 != 0 {
		panic("wrong number of arguments")
	}
	list := make([]snet.PathInterface, (len(args)+2)/3*2-2)
	list[0].IA = xtest.MustParseIA(args[0].(string))
	list[0].ID = common.IFIDType(args[1].(int))
	for i := 2; i < len(args)-2; i += 3 {
		ingress := args[i].(int)
		ia := xtest.MustParseIA(args[i+1].(string))
		egress := args[i+2].(int)
		// two hops: first ingress, then egress
		list[(i-2)/3+1].IA = ia
		list[(i-2)/3+1].ID = common.IFIDType(ingress)
		list[(i-2)/3+2].IA = ia
		list[(i-2)/3+2].ID = common.IFIDType(egress)
	}
	list[len(list)-1].ID = common.IFIDType(args[len(args)-2].(int))
	list[len(list)-1].IA = xtest.MustParseIA(args[len(args)-1].(string))
	return list
}
