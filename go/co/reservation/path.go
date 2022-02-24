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
	slayers "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	spath "github.com/scionproto/scion/go/lib/snet/path"
)

// TransparentPath is used in e.g. setup requests, where the IAs should not be visible.
// They are visible now (as the TransparentPath name implies), but this should change in the future.
type TransparentPath struct {
	CurrentStep int
	Steps       []PathStep // could contain IAs
	RawPath     slayers.Path
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

func (p *TransparentPath) Interfaces() []snet.PathInterface {
	if p == nil {
		return []snet.PathInterface{}
	}
	ifaces := make([]snet.PathInterface, len(p.Steps)*2) // it has two too many
	for i := 0; i < len(p.Steps); i++ {
		ifaces[i*2].ID = common.IFIDType(p.Steps[i].Ingress)
		ifaces[i*2].IA = p.Steps[i].IA
		ifaces[i*2+1].ID = common.IFIDType(p.Steps[i].Egress)
		ifaces[i*2+1].IA = p.Steps[i].IA
	}
	return ifaces[1 : len(ifaces)-1]
}

func (p *TransparentPath) Copy() *TransparentPath {
	var rp slayers.Path
	if p.RawPath != nil {
		buff := make([]byte, p.RawPath.Len())
		if err := p.RawPath.SerializeTo(buff); err != nil {
			panic(fmt.Sprintf("cannot copy path, SerializeTo failed: %s", err))
		}
		rp = PathFromType(p.RawPath.Type())
		if err := rp.DecodeFromBytes(buff); err != nil {
			panic(fmt.Sprintf("cannot copy path, DecodeFromBytes failed: %s", err))
		}
	}
	return &TransparentPath{
		Steps:       append(p.Steps[:0:0], p.Steps...),
		CurrentStep: p.CurrentStep,
		RawPath:     rp,
	}
}

func (p *TransparentPath) String() string {
	if p == nil {
		return "<nil>"
	}
	str := StepsToString(p.Steps)
	if len(str) > 0 {
		str += " "
	}
	str += fmt.Sprintf("[curr.step = %d]", p.CurrentStep)
	return str
}

func (p *TransparentPath) Len() int {
	// currentStep + len(steps) + steps + path_type + rawpath
	var rawPathLen int
	if p.RawPath != nil {
		rawPathLen = p.RawPath.Len()
	}
	return 2 + 2 + len(p.Steps)*pathStepLen + 1 + rawPathLen
}

// Serialize will panic if buff is less bytes than Len().
func (p *TransparentPath) Serialize(buff []byte, options SerializeOptions) {
	if p == nil {
		return
	}
	if p.RawPath == nil {
		// disallow existence of TransparentPath with RawPath==nil
		p.RawPath = &empty.Path{}
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
	if len(raw) < stepCount*pathStepLen {
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
	rp := PathFromType(slayers.Type(raw[0]))
	if rp != nil {
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

func (p *TransparentPath) GetCurrentStep() *PathStep {
	var curr *PathStep
	if p.CurrentStep < len(p.Steps) {
		curr = &p.Steps[p.CurrentStep]
	}
	return curr
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

const pathStepLen = 2 + 2 + 8

func PathFromDataplanePath(p snet.DataplanePath) (slayers.Path, error) {
	// at the moment there is no easy way, without knowing the internals of each DataplanePath,
	// of constructing its equivalent slayers.path.Path
	switch p := p.(type) {
	case spath.Empty, nil:
		return &empty.Path{}, nil
	case spath.OneHop:
		return &onehop.Path{
			Info:      p.Info,
			FirstHop:  p.FirstHop,
			SecondHop: p.SecondHop,
		}, nil
	case path.SCION:
		sp := &scion.Raw{}
		if err := sp.DecodeFromBytes(p.Raw); err != nil {
			return nil, err
		}
		return sp, nil
	case path.Colibri:
		cp := &colibri.ColibriPathMinimal{}
		if err := cp.DecodeFromBytes(p.Raw); err != nil {
			return nil, err
		}
		return cp, nil
	case snet.RawReplyPath:
		return p.Path, nil
	case snet.RawPath:
		rp := PathFromType(p.PathType)
		if err := rp.DecodeFromBytes(p.Raw); err != nil {
			return nil, err
		}
		return rp, nil
	default:
		return nil, serrors.New("unknown path type", "type", common.TypeOf(p))
	}
}

func PathFromType(pt slayers.Type) slayers.Path {
	switch pt {
	case empty.PathType:
		return &empty.Path{}
	case onehop.PathType:
		return &onehop.Path{}
	case scion.PathType:
		return &scion.Raw{}
	case colibri.PathType:
		return &colibri.ColibriPathMinimal{}
	default:
		panic(fmt.Sprintf("unknown path type %s", pt))
	}
}

func PathToRaw(p slayers.Path) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	buff := make([]byte, p.Len())
	err := p.SerializeTo(buff)
	return buff, err
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
