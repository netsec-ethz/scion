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

package reservation

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	utilp "github.com/scionproto/scion/go/lib/util/path"
)

// PathStep encompasses one-hop metadata in COLIBRI
type PathStep struct {
	Ingress uint16
	Egress  uint16
	IA      addr.IA
}

func (s PathStep) Equal(o PathStep) bool {
	return s.Ingress == o.Ingress && s.Egress == o.Egress && s.IA.Equal(o.IA)
}

const PathStepLen = 2 + 2 + 8

// deleteme
// TODO(juagargi) remove the need for this function: the initial path is not used for anything.
// Maybe have the client operator find the path to the next hop in the case of a initial reservation.
func ChoppedPathFromDataplane(dataplanePath snet.DataplanePath) (slayerspath.Path, error) {
	longPath, err := utilp.SnetToDataplanePath(dataplanePath)
	if err != nil {
		return nil, err
	}
	var p *scion.Decoded
	switch v := longPath.(type) {
	case *scion.Raw:
		p = &scion.Decoded{}
		if err = p.DecodeFromBytes(v.Raw); err != nil {
			return nil, err
		}
	case *scion.Decoded:
		p = v
	default:
		return nil, serrors.New(fmt.Sprintf("unknown path type %T", longPath))
	}
	shortPath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen:  [3]uint8{1, 0, 0},
				CurrINF: 0,
				CurrHF:  0,
			},
			NumINF:  1,
			NumHops: 1,
		},
		InfoFields: p.InfoFields[:1],
		HopFields:  p.HopFields[:1],
	}
	return shortPath, nil
}

func ColPathToRaw(p *colpath.ColibriPathMinimal) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	buff := make([]byte, p.Len())
	err := p.SerializeTo(buff)
	return buff, err
}

func ColPathFromRaw(raw []byte) (*colpath.ColibriPathMinimal, error) {
	p := &colpath.ColibriPathMinimal{}
	err := p.DecodeFromBytes(raw)
	return p, err
}

type PathSteps []PathStep

func (p PathSteps) SrcIA() addr.IA {
	return p[0].IA
}

func (p PathSteps) DstIA() addr.IA {
	return p[len(p)-1].IA
}

// Size returns PathSteps size in bytes
func (p PathSteps) Size() int {
	return 2 + len(p)*PathStepLen
}

func (p PathSteps) Serialize(buff []byte) {
	binary.BigEndian.PutUint16(buff, uint16(len(p)))
	buff = buff[2:]
	for _, step := range p {
		binary.BigEndian.PutUint16(buff, step.Ingress)
		binary.BigEndian.PutUint16(buff[2:], step.Egress)
		binary.BigEndian.PutUint64(buff[4:], uint64(step.IA))
		buff = buff[12:]
	}
}

func (p PathSteps) ToRaw() []byte {
	buff := make([]byte, p.Size())
	p.Serialize(buff)
	return buff
}

func PathStepsFromRaw(raw []byte) PathSteps {
	stepCount := int(binary.BigEndian.Uint16(raw))
	raw = raw[2:]
	steps := make([]PathStep, stepCount)
	for i := 0; i < stepCount; i++ {
		steps[i].Ingress = binary.BigEndian.Uint16(raw)
		steps[i].Egress = binary.BigEndian.Uint16(raw[2:])
		steps[i].IA = addr.IA(binary.BigEndian.Uint64(raw[4:]))
		raw = raw[12:]
	}
	return steps
}

func (p PathSteps) Copy() PathSteps {
	return append(p[:0:0], p...)
}

func (p PathSteps) Reverse() PathSteps {
	rev := make([]PathStep, len(p))
	for i, s := range p {
		s.Ingress, s.Egress = s.Egress, s.Ingress
		rev[len(rev)-i-1] = s
	}
	return rev
}

// Interfaces return a snet.PathInterfaces leaving out the leading and trailing
// virtual interfaces.
func (p PathSteps) Interfaces() []snet.PathInterface {
	if p == nil {
		return []snet.PathInterface{}
	}
	ifaces := make([]snet.PathInterface, len(p)*2) // it has two too many
	for i := 0; i < len(p); i++ {
		ifaces[i*2].ID = common.IFIDType(p[i].Ingress)
		ifaces[i*2].IA = p[i].IA
		ifaces[i*2+1].ID = common.IFIDType(p[i].Egress)
		ifaces[i*2+1].IA = p[i].IA
	}
	//
	return ifaces[1 : len(ifaces)-1]
}

func (p PathSteps) String() string {
	strs := make([]string, len(p))
	for i, s := range p {
		if s.IA.IsZero() {
			strs[i] = fmt.Sprintf("%d,%d", s.Ingress, s.Egress)
		} else {
			strs[i] = fmt.Sprintf("%d,%s,%d", s.Ingress, s.IA, s.Egress)
		}
	}
	return strings.Join(strs, " > ")
}

// ValidateEquivalent checks that these steps are compatible with the path.
// Compatible means the ingress/egress interface of the current step is the same
// as those of the raw path if the raw path is colibri, or in the case the raw path
// is of type scion, that the ingress is the same and that the path consists of only 2 hops.
// This is because the regular scion path type can only be used to contact the
// colibri service from the previous colibri service.
// TODO(juagargi) support colibri EER paths
func (s PathSteps) ValidateEquivalent(path slayerspath.Path, atStep int) error {
	var in, eg uint16
	doColibriPath := func(p colpath.ColibriPathFacade) {
		infF := p.GetInfoField()
		if !infF.S {
			panic("colibri EER paths are not yet supported")
		}
		hf := p.GetCurrentHopField()
		in, eg = hf.IngressId, hf.EgressId
		// if using a SegR in a stitching point, ingress or egress could be 0, depending on
		// wether the first segment or the second is being validated
		if infF.S {
			if infF.CurrHF == 0 { // second segment, ignore ingress (it is us)
				in = s[atStep].Ingress
			} else if infF.CurrHF == infF.HFCount-1 { // first segment, ignore egress (it's us)
				eg = s[atStep].Egress
			}
		}
	}
	doScionPath := func(p *scion.Decoded) error {
		// scion path must be 2 hops only
		if p.Base.NumINF != 1 || p.Base.NumHops > 2 {
			return serrors.New("steps not compatible with this scion path: must be direct",
				"inf_count", p.Base.NumINF, "hop_count", p.Base.NumHops,
				"curr_hop", p.Base.PathMeta.CurrHF)
		}
		hf := p.HopFields[p.Base.PathMeta.CurrHF]
		in, eg = hf.ConsIngress, hf.ConsEgress
		if !p.InfoFields[0].ConsDir {
			in = eg
		}
		// always ignore egress
		eg = s[atStep].Egress
		return nil
	}
	switch v := path.(type) {
	case *colpath.ColibriPathMinimal:
		doColibriPath(v)
	case *colpath.ColibriPath:
		doColibriPath(v)
	case *scion.Raw:
		p := &scion.Decoded{}
		if err := p.DecodeFromBytes(v.Raw); err != nil {
			return err
		}
		if err := doScionPath(p); err != nil {
			return err
		}
	case *scion.Decoded:
		if err := doScionPath(v); err != nil {
			return err
		}
	case empty.Path:
		if atStep != 0 {
			return serrors.New("empty path is only allowed at source ASes", "curr_step", atStep)
		}
		return nil // ignore all checks
	default:
		return serrors.New(fmt.Sprintf("Invalid path type %T!\n", v))
	}
	if in != s[atStep].Ingress || eg != s[atStep].Egress {
		return serrors.New("steps and path are not equivalent",
			"path_type", path.Type().String(),
			"path", fmt.Sprintf("[%d,%d]", in, eg),
			"steps", fmt.Sprintf("[%d,%d]", s[atStep].Ingress, s[atStep].Egress))
	}

	return nil
}

func (s PathSteps) Equal(o PathSteps) bool {
	if len(s) != len(o) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !s[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

func StepsFromSnet(p snet.Path) (PathSteps, error) {
	if p == nil {
		return nil, nil
	}
	steps, err := StepsFromInterfaces(p.Metadata().Interfaces)
	if err != nil {
		return nil, err
	}

	return steps, err
}

func StepsFromInterfaces(ifaces []snet.PathInterface) (PathSteps, error) {
	if len(ifaces)%2 != 0 {
		return nil, serrors.New("wrong number of interfaces, not even", "ifaces", ifaces)
	}
	if len(ifaces) == 0 {
		return PathSteps{}, nil
	}
	steps := make([]PathStep, len(ifaces)/2+1)

	for i := 0; i < len(steps)-1; i++ {
		steps[i].Egress = uint16(ifaces[i*2].ID)
		steps[i].IA = ifaces[i*2].IA
		steps[i+1].Ingress = uint16(ifaces[i*2+1].ID)
	}
	steps[len(steps)-1].IA = ifaces[len(ifaces)-1].IA
	return steps, nil
}

func InEgFromDataplanePath(path slayerspath.Path) (uint16, uint16) {
	switch v := path.(type) {
	case *colpath.ColibriPathMinimal:
		return v.CurrHopField.IngressId, v.CurrHopField.EgressId
	case *colpath.ColibriPath:
		curr := v.InfoField.CurrHF
		return v.HopFields[curr].IngressId, v.HopFields[curr].EgressId
	case *scion.Raw:
		inf, err := v.GetCurrentInfoField()
		if err != nil {
			panic(err)
		}
		hf, err := v.GetCurrentHopField()
		if err != nil {
			panic(err)
		}
		if inf.ConsDir {
			return hf.ConsIngress, hf.ConsEgress
		}
		return hf.ConsEgress, hf.ConsIngress
	default:
		panic(fmt.Sprintf("Invalid path type %T!\n", v))
	}
}
