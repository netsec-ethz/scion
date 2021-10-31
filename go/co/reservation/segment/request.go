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
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
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
	PathAtSource     *base.TransparentPath // requested path (maybe different than transport)
	ReverseTraveling bool                  // a down rsv traveling to the core to be re-requested
	Reservation      *Reservation          // nil if no reservation yet
}

func (r *SetupReq) Validate() error {
	if err := r.Request.Validate(); err != nil {
		return err
	}
	if len(r.AllocTrail) > len(r.Path.Steps) {
		return serrors.New("inconsistent trail and setup path", "trail", r.AllocTrail,
			"path", r.Path)
	}
	if err := r.PathProps.ValidateWithPathType(r.PathType); err != nil {
		return serrors.New("incompatible path type and props", "path_type", r.PathType,
			"props", r.PathProps)
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

func (r *SetupReq) Len() int {
	// basic_request + expTime + RLC + pathType + minBW + maxBW + splitCls + pathProps
	return r.Request.Len() + 4 + 1 + 1 + 1 + 1 + 1 + 1
}

func (r *SetupReq) Serialize(buff []byte, options base.SerializeOptions) {
	offset := r.Request.Len()
	r.Request.Serialize(buff[:offset], options)

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
