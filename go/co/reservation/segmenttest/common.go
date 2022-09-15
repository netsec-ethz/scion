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

package segmenttest

import (
	"fmt"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func NewReservation() *segment.Reservation {
	return NewRsv(
		WithID("ff00:0:1", "beefcafe"),
		WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"))
}

// ReservationMod allows the configuration of reservations via function calls, aka
// functional options.
// As this signature is used only in tests, it doesn't return an error: it assumes that
// the function implementing the option will panic if error.
type ReservationMod func(*segment.Reservation) *segment.Reservation

// NewRsv creates a reservation configured via functional options.
func NewRsv(mods ...ReservationMod) *segment.Reservation {
	rsv := segment.NewReservation(addr.AS(0))
	return ModRsv(rsv, mods...)
}

// ModRsv simply modifies an existing reservation via functional options.
func ModRsv(rsv *segment.Reservation, mods ...ReservationMod) *segment.Reservation {
	for _, mod := range mods {
		rsv = mod(rsv)
	}
	return rsv
}

// NewRsvs creates a number of reservations configured via functional options.
func NewRsvs(n int, mods ...ReservationMod) []*segment.Reservation {
	rsvs := make([]*segment.Reservation, n)
	for i := 0; i < n; i++ {
		rsvs[i] = NewRsv(mods...)
	}
	return rsvs
}

// ModRsvs modifies existing reservations  via functional options.
func ModRsvs(rsvs []*segment.Reservation, mods ...ReservationMod) {
	for i, rsv := range rsvs {
		for _, mod := range mods {
			rsv = mod(rsv)
		}
		rsvs[i] = rsv
	}
}

// WithID sets the ID specified with as and suffix to the reservation.
func WithID(as, suffix string) ReservationMod {
	as_ := xtest.MustParseAS(as)
	id, err := reservation.NewID(as_, xtest.MustParseHexString(suffix))
	if err != nil {
		panic(err)
	}
	return func(rsv *segment.Reservation) *segment.Reservation {
		rsv.ID = *id
		return rsv
	}
}

func WithPath(path ...interface{}) ReservationMod {
	snetPath := test.NewSnetPath(path...)
	steps, err := base.StepsFromSnet(snetPath)
	if err != nil {
		panic(err)
	}
	rawPath, err := base.PathFromDataplanePath(snetPath.Dataplane())
	if err != nil {
		panic(err)
	}
	return func(rsv *segment.Reservation) *segment.Reservation {
		rsv.Steps = steps
		rsv.TransportPath = rawPath
		rsv.Ingress, rsv.Egress = base.InEgFromDataplanePath(rsv.TransportPath)
		return rsv
	}
}

func WithIngressEgress(ig, eg int) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		if ig > 0 {
			rsv.Ingress = uint16(ig)
		}
		if eg > 0 {
			rsv.Egress = uint16(eg)
		}
		return rsv
	}
}

func WithTrafficSplit(split int) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		rsv.TrafficSplit = reservation.SplitCls(split)
		return rsv
	}
}

func WithEndProps(endProps reservation.PathEndProps) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		rsv.PathEndProps = endProps
		return rsv
	}
}

func WithPathType(pathType reservation.PathType) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		rsv.PathType = pathType
		return rsv
	}
}

// WithActiveIndex sets the index specified with idx as active.
func WithActiveIndex(idx int) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		if err := rsv.SetIndexConfirmed(reservation.IndexNumber(idx)); err != nil {
			panic(err)
		}
		if err := rsv.SetIndexActive(reservation.IndexNumber(idx)); err != nil {
			panic(err)
		}
		return rsv
	}
}

// WithNoActiveIndex resets the active index to confirmed, if any active index exists.
func WithNoActiveIndex() ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		if act := rsv.ActiveIndex(); act != nil {
			rsv.RemoveIndex(act.Idx)
			newIdx := segment.Index{
				Idx:        act.Idx,
				Expiration: act.Expiration,
				MinBW:      act.MinBW,
				MaxBW:      act.MaxBW,
				AllocBW:    act.AllocBW,
				Token:      act.Token,
			}
			// the active reservation is always the first one: place newIdx there
			rsv.Indices = append(append(rsv.Indices[:0:0], newIdx), rsv.Indices...)
			rsv.SetIndexConfirmed(newIdx.Idx)
		}
		return rsv
	}
}

func ConfirmAllIndices() ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		if rsv == nil || rsv.Indices.Len() == 0 {
			return rsv
		}
		for _, idx := range rsv.Indices {
			if idx.State != segment.IndexActive {
				if err := rsv.SetIndexConfirmed(idx.Idx); err != nil {
					panic(err)
				}
			}
		}
		return rsv
	}
}

// IndexMod allows the creation of indices with parameters via functional configuration.
// This type doesn't return an error, thus assumes the functional option will panic or ignore
// the error.
type IndexMod func(*segment.Index)

// AddIndex adds a new index, modified via functional options, to the reservation.
func AddIndex(idx int, mods ...IndexMod) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		expTime := util.SecsToTime(0)
		if rsv.Indices.Len() > 0 {
			expTime = rsv.Indices.GetExpiration(rsv.Indices.Len() - 1)
		}
		idx, err := rsv.NewIndex(reservation.IndexNumber(idx), expTime, 0, 0, 0, 0, 0)
		if err != nil {
			panic(err)
		}
		index := rsv.Index(idx)
		for _, mod := range mods {
			mod(index)
		}
		return rsv
	}
}

// ModIndex applies the functional options to the index specified.
func ModIndex(idx reservation.IndexNumber, mods ...IndexMod) ReservationMod {
	return func(rsv *segment.Reservation) *segment.Reservation {
		index := rsv.Index(idx)
		if index == nil {
			panic(fmt.Errorf("index is nil. idx = %d, len = %d", idx, rsv.Indices.Len()))
		}
		for _, mod := range mods {
			mod(index)
		}
		return rsv
	}
}

// WithBW changes the min, max and/or alloc BW if their values are > 0.
func WithBW(min, max, alloc int) IndexMod {
	return func(index *segment.Index) {
		if min > 0 {
			index.MinBW = reservation.BWCls(min)
		}
		if max > 0 {
			index.MaxBW = reservation.BWCls(max)
		}
		if alloc > 0 {
			index.AllocBW = reservation.BWCls(alloc)
		}
	}
}

// WithExpiration sets the expiration to the index (and its token).
func WithExpiration(exp time.Time) IndexMod {
	return func(index *segment.Index) {
		index.Expiration = exp
		index.Token.ExpirationTick = reservation.TickFromTime(exp)
	}
}
