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
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	slayers "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
)

func MustParseID(asid, suffix string) *col.ID {
	id, err := col.NewID(xtest.MustParseAS(asid), xtest.MustParseHexString(suffix))
	if err != nil {
		panic(err)
	}
	return id
}

func NewSnetPathWithHop(args ...interface{}) snet.Path {
	ifaces := NewIfaces(args...)
	steps, err := base.StepsFromInterfaces(ifaces)
	if err != nil {
		panic(err)
	}

	rp := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  1,
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
	buff := make([]byte, rp.Len())
	err = rp.SerializeTo(buff)
	if err != nil {
		panic(err)
	}

	return path.Path{
		Meta: snet.PathMetadata{
			Interfaces: ifaces,
		},
		DataplanePath: path.SCION{
			Raw: buff,
		},
	}
}
