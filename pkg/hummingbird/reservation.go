// Copyright 2024 ETH Zurich
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

package hummingbird

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Reservation represents a possibly partially reserved path, with zero or more flyovers.
type Reservation struct {
	dec   *hummingbird.Decoded // caches a decoded path for multiple uses
	hops  []Hop                // possible flyovers, one per dec.HopField that has a flyover.
	now   time.Time            // the current time
	minBW uint16               // the minimum required bandwidth

	counter uint32 // duplicate detection counter
}

type Hop struct {
	Hopfield *hummingbird.FlyoverHopField // dataplane hop field
	Flyover  *Flyover                     // flyover used to build this hop
}

// NewReservation creates a new reservation object. The option setting functions are executed in
// the order they appear in the slice.
func NewReservation(opts ...reservationModFcn) (*Reservation, error) {
	r := &Reservation{
		now: time.Now(),
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// reservationModFcn is a options setting function for a reservation.
type reservationModFcn func(*Reservation) error

// WithScionPath allows to build a Reservation based on the SCION path and flyovers passed as
// arguments.
// The flyovers are chosen from the map in order of appearance iff they are suitable, i.e. if
// they have a validity period intersecting with now.
func WithScionPath(p snet.Path, flyovers FlyoverMap) reservationModFcn {
	return func(r *Reservation) error {
		switch p := p.Dataplane().(type) {
		case path.SCION:
			scion := scion.Decoded{}
			if err := scion.DecodeFromBytes(p.Raw); err != nil {
				return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
			}
			r.dec = &hummingbird.Decoded{}
			r.dec.ConvertFromScionDecoded(scion)
		default:
			return serrors.New("Unsupported path type")
		}

		// We use the path metadata to get the IA from it. This sequence of interfaces does not
		// include the egress-to-ingress crossed over interfaces in the core AS.
		interfaces := p.Metadata().Interfaces

		// Add the first hop of the first segment now.
		r.newHopSelectFlyover(
			interfaces[0].IA,
			0,
			uint16(interfaces[0].ID),
			0,
			flyovers,
		)

		// The dataplane path in c.dec contains inf fields and cross-over hops.
		// Do each segment at a time to ignore the first hop of every segment
		// (the first segment's first hop was already added above).
		dpHopIdx := uint8(1) // the index of the current hop in the dataplane.
		interfaceCount := 1  // the index of the interfaces (no cross overs).
		for infIdx := 0; infIdx < r.dec.NumINF; infIdx, dpHopIdx = infIdx+1, dpHopIdx+1 {
			// Preserve the hop count locally, as we modify the path inside the loop itself.
			hopCount := int(r.dec.Base.PathMeta.SegLen[infIdx]) / hummingbird.HopLines
			for i := 1; i < hopCount; i, dpHopIdx = i+1, dpHopIdx+1 {
				r.newHopSelectFlyover(
					interfaces[interfaceCount*2-1].IA,
					uint16(interfaces[interfaceCount*2-1].ID),
					egressID(interfaces, interfaceCount),
					dpHopIdx,
					flyovers,
				)
				interfaceCount++
			}
		}

		return nil
	}
}

// WithExistingHbirdPath allows to create a Reservation from an existing Hummingbird decoded
// path and its corresponding hop sequence.
func WithExistingHbirdPath(p *hummingbird.Decoded, flyovers []*Flyover) reservationModFcn {
	// func WithExistingHbirdPath(p *hummingbird.Decoded, hops []Hop) reservationModFcn {
	return func(r *Reservation) error {
		r.dec = p
		// Create as many hops as non nil flyovers.
		for i, flyover := range flyovers {
			if flyover == nil {
				continue
			}
			r.newHop(flyover.IA, flyover.Ingress, flyover.Egress, uint8(i), flyover)
		}
		// For each hop field, clean up the ResStartTime as it's set when deriving the dataplane
		// path.
		for i := range r.dec.HopFields {
			r.dec.HopFields[i].ResStartTime = 0
		}

		return nil
	}
}

// WithNow modifies the current point in time for this reservation. It is useful to filter
// the different flyovers that can be passed to WithScionPath.
func WithNow(now time.Time) reservationModFcn {
	return func(r *Reservation) error {
		r.now = now
		return nil
	}
}

// WithMinBW modifies the minimum bandwidth required when filtering flyovers at the time of
// reservation creation.
func WithMinBW(bw uint16) reservationModFcn {
	return func(r *Reservation) error {
		r.minBW = bw
		return nil
	}
}

func (r *Reservation) Destination() addr.IA {
	return r.hops[len(r.hops)-1].Flyover.IA
}

func (r *Reservation) GetHummingbirdPath() *hummingbird.Decoded {
	return r.dec
}

// FlyoverPerHopField returns a slice of pointers to flyovers, one per hop field present in the path,
// i.e. the length of the slice is the hop field count.
// If a hop field is not covered by a flyover, nil is used in its place.
func (r *Reservation) FlyoverPerHopField() []*Flyover {
	flyovers := make([]*Flyover, len(r.dec.HopFields))
	for hopIdx, i := 0, 0; i < len(flyovers) && hopIdx < len(r.hops); i++ {
		var flyover *Flyover
		if r.hops[hopIdx].Hopfield == &r.dec.HopFields[i] {
			flyover = r.hops[hopIdx].Flyover
			hopIdx++
		}
		flyovers[i] = flyover
	}

	return flyovers
}

func (r *Reservation) FlyoverAndHFCount() (int, int) {
	return len(r.hops), len(r.dec.HopFields)
}

// DeriveDataPlanePath sets pathmeta timestamps and increments duplicate detection counter and
// updates MACs of all flyoverfields.
func (r *Reservation) DeriveDataPlanePath(
	pktLen uint16,
	timeStamp time.Time,
) *hummingbird.Decoded {

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	millis |= r.counter
	r.dec.Base.PathMeta.BaseTS = secs
	r.dec.Base.PathMeta.HighResTS = millis
	//increment counter for next packet
	if r.counter >= 1<<22-1 {
		r.counter = 0
	} else {
		r.counter += 1
	}
	// compute Macs for Flyovers
	var byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	var xkbuffer [hummingbird.XkBufferSize]uint32
	for _, h := range r.hops {
		if !h.Hopfield.Flyover {
			continue
		}
		h.Hopfield.ResStartTime = uint16(secs - h.Flyover.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(h.Flyover.Ak[:], r.Destination(), pktLen,
			h.Hopfield.ResStartTime, millis, byteBuffer[:], xkbuffer[:])

		binary.BigEndian.PutUint32(h.Hopfield.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(h.Hopfield.HopField.Mac[:4]))
		binary.BigEndian.PutUint16(h.Hopfield.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(h.Hopfield.HopField.Mac[4:]))
	}

	return r.dec
}

func (r *Reservation) newHopSelectFlyover(ia addr.IA, in, eg uint16,
	hfIdx uint8, flyoverSet FlyoverMap) {

	// Look for a valid flyover.
	now := uint32(r.now.Unix())
	k := BaseHop{
		IA:      ia,
		Ingress: in,
		Egress:  eg,
	}
	flyovers := flyoverSet[k]
	for _, flyover := range flyovers {
		if flyover.StartTime <= now && uint32(flyover.Duration) >= now-flyover.StartTime &&
			flyover.Bw >= r.minBW {

			r.newHop(ia, in, eg, hfIdx, flyover)
			break
		}
	}
}

func (r *Reservation) newHop(ia addr.IA, in, eg uint16,
	hfIdx uint8, flyover *Flyover) {

	// Find the hop field from its index.
	hf := &r.dec.HopFields[hfIdx]

	if !hf.Flyover {
		// Because we are setting a plain hop field as a flyover, it will use two more lines.
		r.dec.NumLines += 2
		r.dec.PathMeta.SegLen[r.dec.InfIndexForHFIndex(hfIdx)] += 2
		hf.Flyover = true
	}

	hf.Bw = flyover.Bw
	hf.Duration = flyover.Duration
	hf.ResID = flyover.ResID
	r.hops = append(r.hops, Hop{
		Hopfield: hf,
		Flyover:  flyover,
	})
}

// egressID returns the egress ID from a sequence of IDs (such as that in the metadata field
// of a snet.Path) given its index. If index is past the length of the sequence, the egress
// ID 0 is returning, meaning egress ID is that last AS.
func egressID(ifaces []snet.PathInterface, idx int) uint16 {
	i := idx * 2
	if i >= len(ifaces) {
		return 0
	}
	return uint16(ifaces[i].ID)
}

// FlyoverMap is a map between a flyover IA,ingress,egress and its corresponding collection of
// flyover objects (each of them can have e.g. different starting times).
type FlyoverMap map[BaseHop][]*Flyover

func FlyoversToMap(flyovers []*Flyover) FlyoverMap {
	ret := make(FlyoverMap)
	for _, flyover := range flyovers {
		k := BaseHop{
			IA:      flyover.IA,
			Ingress: flyover.Ingress,
			Egress:  flyover.Egress,
		}
		ret[k] = append(ret[k], flyover)
	}
	return ret
}
