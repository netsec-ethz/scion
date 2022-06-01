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
	"github.com/scionproto/scion/go/lib/slayers"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
)

func GetCurrentHopField(path slayerspath.Path) uint8 {
	switch v := path.(type) {
	case *colibri.ColibriPath:
		return v.InfoField.CurrHF
	case *colibri.ColibriPathMinimal:
		return v.InfoField.CurrHF
	case *scion.Raw:
		return v.PathMeta.CurrHF
	case empty.Path:
		// TODO(JordiSubira): temporary hack, this value will be override with the E2ERequest currentStep.
		// Remove this once we convery E2ESetup request over Colibri path.
		return 0
	default:
		panic(fmt.Sprintf("Invalid path type %T!\n", v))
	}
}

func EgressFromDataPlanePath(path slayerspath.Path) uint16 {
	switch v := path.(type) {
	case *colibri.ColibriPathMinimal:
		return v.CurrHopField.EgressId
	case *colibri.ColibriPath:
		curr := v.InfoField.CurrHF
		return v.HopFields[curr].EgressId
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
			return hf.ConsEgress
		}
		return hf.ConsIngress
	default:
		panic(fmt.Sprintf("Invalid path type %T!\n", v))
	}
}

func IngressFromDataPlanePath(path slayerspath.Path) uint16 {
	switch v := path.(type) {
	case *colibri.ColibriPathMinimal:
		return v.CurrHopField.IngressId
	case *colibri.ColibriPath:
		curr := v.InfoField.CurrHF
		return v.HopFields[curr].IngressId
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
			return hf.ConsIngress
		}
		return hf.ConsEgress
	default:
		panic(fmt.Sprintf("Invalid path type %T!\n", v))
	}
}

// TransparentPath is used in e.g. setup requests, where the IAs should not be visible.
// They are visible now (as the TransparentPath name implies), but this should change in the future.
type TransparentPath struct {
	CurrentStep int
	Steps       []PathStep // could contain IAs
	RawPath     slayerspath.Path
}

// TODO(juagargi) since the introduction the DataplanePath the implementation of TransparentPath
// has changed significantly. Too many panic calls. It should actually be a snet.Path exposing
// extra things like current step.

func TransparentPathFromSnet(p snet.Path) (*TransparentPath, error) {
	if p == nil {
		return nil, nil
	}
	transp, err := TransparentPathFromInterfaces(p.Metadata().Interfaces)
	if err != nil {
		return transp, err
	}

	transp.RawPath, err = PathFromDataplanePath(p.Dataplane())
	return transp, err
}

// TransparentPathFromInterfaces constructs an TransparentPath given a list of snet.PathInterface .
// from a scion path e.g. 1-1#1, 1-2#33, 1-2#44, i-3#2.
func TransparentPathFromInterfaces(ifaces []snet.PathInterface) (*TransparentPath, error) {
	if len(ifaces)%2 != 0 {
		return nil, serrors.New("wrong number of interfaces, not even", "ifaces", ifaces)
	}
	if len(ifaces) == 0 {
		return &TransparentPath{Steps: []PathStep{}}, nil
	}
	transp := &TransparentPath{
		Steps: make([]PathStep, len(ifaces)/2+1),
	}

	for i := 0; i < len(transp.Steps)-1; i++ {
		transp.Steps[i].Egress = uint16(ifaces[i*2].ID)
		transp.Steps[i].IA = ifaces[i*2].IA
		transp.Steps[i+1].Ingress = uint16(ifaces[i*2+1].ID)
	}
	transp.Steps[len(transp.Steps)-1].IA = ifaces[len(ifaces)-1].IA
	return transp, nil
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

// TransparentPathFromInterfaces constructs an TransparentPath given a list of snet.PathInterface .
// from a scion path e.g. 1-1#1, 1-2#33, 1-2#44, i-3#2.
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

func (p *TransparentPath) String() string {
	if p == nil {
		return "<nil>"
	}
	str := StepsToString(p.Steps)
	if len(str) > 0 {
		str += " "
	}
	rawpath := "<nil>"
	if p.RawPath != nil {
		rawpath = p.RawPath.Type().String()
	}
	str += fmt.Sprintf("[curr.step = %d, rawpath = %s]", p.CurrentStep, rawpath)
	return str
}

func (p *TransparentPath) Len() int {
	// currentStep + len(steps) + steps + path_type + rawpath
	var rawPathLen int
	if p.RawPath != nil {
		rawPathLen = p.RawPath.Len()
	}
	return 2 + 2 + len(p.Steps)*PathStepLen + 1 + rawPathLen
}

// Serialize will panic if buff is less bytes than Len().
func (p *TransparentPath) Serialize(buff []byte, options SerializeOptions) {
	if p == nil {
		return
	}
	if p.RawPath == nil {
		// disallow existence of TransparentPath with RawPath==nil
		p.RawPath = empty.Path{}
	}
	if options == SerializeMutable {
		binary.BigEndian.PutUint16(buff, uint16(p.CurrentStep))
	}
	buff = buff[2:]
	binary.BigEndian.PutUint16(buff, uint16(len(p.Steps)))
	buff = buff[2:]
	for _, step := range p.Steps {
		binary.BigEndian.PutUint16(buff, step.Ingress)
		binary.BigEndian.PutUint16(buff[2:], step.Egress)
		binary.BigEndian.PutUint64(buff[4:], uint64(step.IA))
		buff = buff[12:]
	}
	buff[0] = byte(p.RawPath.Type())
	if options == SerializeMutable {
		if err := p.RawPath.SerializeTo(buff[1:]); err != nil {
			panic(fmt.Sprintf("cannot serialize path: %s", err))
		}
	}
}

func (p *TransparentPath) ToRaw() []byte {
	if p == nil {
		return []byte{}
	}

	buff := make([]byte, p.Len())
	p.Serialize(buff, SerializeMutable)
	return buff
}

func TransparentPathFromRaw(raw []byte) (*TransparentPath, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// currentStep + len(steps) + steps + path_type + rawpath
	if len(raw) < 5 {
		return nil, serrors.New("buffer too small")
	}
	currStep := int(binary.BigEndian.Uint16(raw))
	raw = raw[2:]
	stepCount := int(binary.BigEndian.Uint16(raw))
	raw = raw[2:]
	if len(raw) < stepCount*PathStepLen {
		return nil, serrors.New("buffer too small for these path", "step_count", stepCount,
			"len", len(raw))
	}
	steps := make([]PathStep, stepCount)
	for i := 0; i < stepCount; i++ {
		steps[i].Ingress = binary.BigEndian.Uint16(raw)
		steps[i].Egress = binary.BigEndian.Uint16(raw[2:])
		steps[i].IA = addr.IA(binary.BigEndian.Uint64(raw[4:]))
		raw = raw[12:]
	}
	rp, err := slayerspath.NewPath(slayerspath.Type(raw[0]))
	if err == nil && rp != nil {
		if err := rp.DecodeFromBytes(raw[1:]); err != nil {
			return nil, err
		}
	}
	return &TransparentPath{
		CurrentStep: currStep,
		Steps:       steps,
		RawPath:     rp,
	}, nil
}

func (p *TransparentPath) SrcIA() addr.IA {
	if p == nil {
		return 0
	}
	return p.Steps[0].IA
}

func (p *TransparentPath) DstIA() addr.IA {
	if p == nil || len(p.Steps) == 0 {
		return 0
	}
	return p.Steps[len(p.Steps)-1].IA
}

func (p *TransparentPath) Validate() error {
	if p == nil {
		return nil
	}
	// sometimes we'll have requests with one step only (e.g. teardown after bad setup)
	if len(p.Steps) < 1 {
		return serrors.New("wrong number of steps", "count", len(p.Steps))
	}
	if p.CurrentStep >= len(p.Steps) {
		return serrors.New("current step out of bounds", "curr_step", p.CurrentStep,
			"count", len(p.Steps))
	}
	return nil
}

func (p *TransparentPath) Reverse() error {
	if p == nil {
		return nil
	}
	rev := make([]PathStep, len(p.Steps))
	for i, s := range p.Steps {
		s.Ingress, s.Egress = s.Egress, s.Ingress
		rev[len(rev)-i-1] = s
	}
	p.Steps = rev
	if p.CurrentStep < len(rev) { // if curr step is past the last item, leave it as is.
		p.CurrentStep = len(rev) - p.CurrentStep - 1
	}
	// step for UTs: comparisons between empty slices and nil slices always fail.
	// if the raw path is nil, then don't reverse anything.
	if p.RawPath == nil {
		return nil
	}
	var err error
	p.RawPath, err = p.RawPath.Reverse()
	return err
}

// PathStep is one hop of the TransparentPath.
// For a source AS: Ingress will be invalid. Conversely for dst.
// So as opposed to snet.Path, these paths have length = number of ASes in the path.
type PathStep struct {
	Ingress uint16
	Egress  uint16
	IA      addr.IA
}

const PathStepLen = 2 + 2 + 8

func PathFromDataplanePath(p snet.DataplanePath) (slayerspath.Path, error) {
	var s slayers.SCION
	err := p.SetPath(&s)
	return s.Path, err
}

func PathToRaw(p slayerspath.Path) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	buff := make([]byte, p.Len()+1)
	buff[0] = byte(p.Type())
	err := p.SerializeTo(buff[1:])
	return buff, err
}

func PathFromRaw(raw []byte) (slayerspath.Path, error) {
	rp, err := slayerspath.NewPath(slayerspath.Type(raw[0]))
	if err == nil && rp != nil {
		if err := rp.DecodeFromBytes(raw[1:]); err != nil {
			return nil, err
		}
	}
	return rp, nil
}

func StepsToString(steps []PathStep) string {
	strs := make([]string, len(steps))
	for i, s := range steps {
		if s.IA.IsZero() {
			strs[i] = fmt.Sprintf("%d,%d", s.Ingress, s.Egress)
		} else {
			strs[i] = fmt.Sprintf("%d,%s,%d", s.Ingress, s.IA, s.Egress)
		}
	}
	return strings.Join(strs, " > ")
}

type PathSteps []PathStep

func (p PathSteps) SrcIA() addr.IA {
	if p == nil {
		return 0
	}
	return p[0].IA
}

func (p PathSteps) DstIA() addr.IA {
	if p == nil || len(p) == 0 {
		return 0
	}
	return p[len(p)-1].IA
}

func (p PathSteps) Step(i int) (PathStep, error) {
	if p == nil || i >= len(p) {
		return PathStep{}, serrors.New("wrong index", "idx", i, "len", len(p))
	}
	return p[i], nil
}

func (p PathSteps) Len() int {
	return 2 + len(p)*PathStepLen
}

func (p PathSteps) Serialize(buff []byte) {
	if len(buff) < p.Len() {
		panic("short buffer")
	}
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
	if p == nil {
		return []byte{}
	}

	buff := make([]byte, p.Len())
	p.Serialize(buff)
	return buff
}

func PathStepsFromRaw(raw []byte) (PathSteps, error) {
	stepCount := int(binary.BigEndian.Uint16(raw))
	raw = raw[2:]
	if len(raw) < stepCount*PathStepLen {
		return nil, serrors.New("buffer too small for these path", "step_count", stepCount,
			"len", len(raw))
	}
	steps := make([]PathStep, stepCount)
	for i := 0; i < stepCount; i++ {
		steps[i].Ingress = binary.BigEndian.Uint16(raw)
		steps[i].Egress = binary.BigEndian.Uint16(raw[2:])
		steps[i].IA = addr.IA(binary.BigEndian.Uint64(raw[4:]))
		raw = raw[12:]
	}
	return steps, nil
}

func (p PathSteps) Copy() PathSteps {
	return append(p[:0:0], p...)
}

func (p PathSteps) Reverse() PathSteps {
	if p == nil {
		return p
	}
	rev := make([]PathStep, len(p))
	for i, s := range p {
		s.Ingress, s.Egress = s.Egress, s.Ingress
		rev[len(rev)-i-1] = s
	}
	return rev
}

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
	return ifaces[1 : len(ifaces)-1]
}
