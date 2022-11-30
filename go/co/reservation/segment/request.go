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

package segment

import (
	"encoding/binary"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/util"
)

// SetupReq is a segment reservation setup request.
// This same type is used for renewal of the segment reservation.
type SetupReq struct {
	base.Request

	ExpirationTime   time.Time
	RLC              reservation.RLC
	PathType         reservation.PathType
	MinBW            reservation.BWCls
	MaxBW            reservation.BWCls
	SplitCls         reservation.SplitCls
	PathProps        reservation.PathEndProps
	AllocTrail       reservation.AllocationBeads
	ReverseTraveling bool // a down rsv traveling to the core to be re-requested
	// TODO(juagargi) remove Reservation from this type
	Reservation   *Reservation                // nil if no reservation yet
	Steps         base.PathSteps              // retrieved from pb request (except at source)
	CurrentStep   int                         // recovered from pb request (except at source)
	TransportPath *colibri.ColibriPathMinimal // recovered from dataplane (except at source)
}

// Validate takes as argument a function that returns the neighboring IA given the
// interface ID. When 0, the function must return the local IA.
// Validate returns an error if not valid, or nil if okay.
func (r *SetupReq) Validate(getNeighborIA func(ifaceID uint16) addr.IA) error {
	if err := r.Request.Validate(r.Steps); err != nil {
		return err
	}
	if len(r.AllocTrail) > len(r.Steps) {
		return serrors.New("inconsistent trail and setup path", "trail", r.AllocTrail,
			"path", r.Steps)
	}
	if err := r.PathProps.ValidateWithPathType(r.PathType); err != nil {
		return serrors.New("incompatible path type and props", "path_type", r.PathType,
			"props", r.PathProps)
	}
	if r.Steps == nil || len(r.Steps) < 2 {
		return serrors.New("Wrong steps state")
	}
	if r.CurrentStep < 0 || r.CurrentStep >= len(r.Steps) {
		return serrors.New("invalid current step for the given steps", "currentStep", r.CurrentStep,
			"steps len", len(r.Steps))
	}
	if r.Steps[0].Ingress != 0 {
		return serrors.New("Wrong interface for srcIA ingress",
			"ingress", r.Steps[0].Ingress)
	}
	if r.Steps[len(r.Steps)-1].Egress != 0 {
		return serrors.New("Wrong interface for dstIA egress",
			"egress", r.Steps[len(r.Steps)-1].Egress)
	}
	if err := r.Steps.ValidateEquivalent(r.TransportPath, r.CurrentStep); err != nil {
		return serrors.WrapStr("invalid steps/raw path", err)
	}
	// previous IA correct?
	if r.CurrentStep > 0 &&
		getNeighborIA(r.Ingress()) != r.Steps[r.CurrentStep-1].IA {
		return serrors.New("previous IA according to steps and topology not same",
			"steps", r.Steps[r.CurrentStep-1].IA,
			"topo", getNeighborIA(r.Ingress()))
	}
	// this IA correct?
	if r.Steps[r.CurrentStep].IA != getNeighborIA(0) {
		return serrors.New("current IA according to steps not same as local",
			"steps", r.Steps[r.CurrentStep].IA,
			"local", getNeighborIA(0))
	}
	// next IA correct?
	if r.CurrentStep+1 < len(r.Steps) &&
		getNeighborIA(r.Egress()) != r.Steps[r.CurrentStep+1].IA {
		return serrors.New("next IA according to steps and topology not same",
			"steps", r.Steps[r.CurrentStep+1].IA,
			"topo", getNeighborIA(r.Egress()))
	}
	return nil
}

func (r *SetupReq) ValidateForReservation(rsv *Reservation) error {
	if r.PathType != rsv.PathType {
		return serrors.New("different path type", "req", r.PathType, "rsv", rsv.PathType)
	}
	if r.PathProps != rsv.PathEndProps {
		return serrors.New("different path end props.", "req", r.PathProps, "rsv", rsv.PathEndProps)
	}
	return nil
}

// Ingress returns the ingress interface of this step for this request.
// Do not call Ingress without validating the request first.
func (r *SetupReq) Ingress() uint16 {
	return r.Steps[r.CurrentStep].Ingress
}

// Egress returns the egress interface of this step for this request.
// Do not call Egress without validating the request first.
func (r *SetupReq) Egress() uint16 {
	return r.Steps[r.CurrentStep].Egress
}

// TakeStep indicates a new hop has been taken (it usually increments CurrentStep, depending on
// whether this is a down path reservation or not).
func (r *SetupReq) TakeStep() {
	var inc int
	if r.ReverseTraveling {
		inc = -1
	} else {
		inc = +1
	}
	r.CurrentStep += inc
}

func (r *SetupReq) Transport() *colibri.ColibriPathMinimal {
	return r.TransportPath
}

func (r *SetupReq) Len() int {
	// basic_request + steps len + expTime + RLC + pathType + minBW + maxBW + splitCls + pathProps
	return r.Request.Len() + r.Steps.Size() + 4 + 1 + 1 + 1 + 1 + 1 + 1
}

func (r *SetupReq) Serialize(buff []byte, options base.SerializeOptions) {
	r.Request.Serialize(buff[:], options)
	offset := r.Request.Len()
	r.Steps.Serialize(buff[offset:])
	offset += r.Steps.Size()

	binary.BigEndian.PutUint32(buff[offset:], util.TimeToSecs(r.ExpirationTime))
	offset += 4
	buff[offset] = byte(r.RLC)
	buff[offset+1] = byte(r.PathType)
	buff[offset+2] = byte(r.MinBW)
	buff[offset+3] = byte(r.MaxBW)
	buff[offset+4] = byte(r.SplitCls)
	buff[offset+5] = byte(r.PathProps)
	if options >= base.SerializeSemiMutable {
		offset += 6
		for _, bead := range r.AllocTrail {
			buff[offset] = byte(bead.AllocBW)
			buff[offset+1] = byte(bead.MaxBW)
			offset += 2
		}
	}
}

// PrevBW returns the minimum of the maximum bandwidths already granted by previous ASes.
func (r *SetupReq) PrevBW() uint64 {
	if len(r.AllocTrail) == 0 {
		return r.MaxBW.ToKbps()
	}
	return r.AllocTrail.MinMax().ToKbps()
}
