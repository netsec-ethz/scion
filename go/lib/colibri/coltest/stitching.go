// Copyright 2021 ETH Zurich
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

// Package colibri contains methods for the creation and verification of the colibri packet
// timestamp and validation fields.
package coltest

import (
	"fmt"

	base "github.com/scionproto/scion/go/co/reservation"
	rt "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

type stitchableGenerator struct {
	stitchable                 *colibri.StitchableSegments
	cores                      []addr.IA
	lastup, lastcore, lastdown int
}

func (g *stitchableGenerator) newUpID() reservation.ID {
	g.lastup++
	id := reservation.ID{
		ASID: g.stitchable.SrcIA.AS(),
	}
	id.SetSegmentSuffix(g.lastup)
	return id
}

func (g *stitchableGenerator) newDownID() reservation.ID {
	g.lastdown++
	id := reservation.ID{
		ASID: g.stitchable.DstIA.AS(),
	}
	id.SetSegmentSuffix(g.lastdown)
	return id
}

func (g *stitchableGenerator) newCoreID(asid addr.IA) reservation.ID {
	g.lastcore++
	id := reservation.ID{
		ASID: asid.AS(),
	}
	id.SetSegmentSuffix(g.lastcore)
	return id
}

type StitchableMod func(*stitchableGenerator)

func NewStitchableSegments(src, dst string, mods ...StitchableMod) *colibri.StitchableSegments {
	stitchable := &colibri.StitchableSegments{
		SrcIA: xtest.MustParseIA(src),
		DstIA: xtest.MustParseIA(dst),
	}
	generator := &stitchableGenerator{
		stitchable: stitchable,
	}
	for _, mod := range mods {
		mod(generator)
	}
	return stitchable
}

type segTypeSelector int

const (
	Up segTypeSelector = iota
	Core
	Down
)

type bwselector int

const (
	Minbw bwselector = iota
	Maxbw
	Allocbw
)

func WithBW(segType segTypeSelector, idx int, selector bwselector,
	bw reservation.BWCls) StitchableMod {

	return func(generator *stitchableGenerator) {
		l := findInGenerator(generator, segType, idx)
		switch selector {
		case Minbw:
			l.MinBW = bw
		case Maxbw:
			l.MaxBW = bw
		case Allocbw:
			l.AllocBW = bw
		}
	}
}

func WithSplit(segType segTypeSelector, idx int, split reservation.SplitCls) StitchableMod {
	return func(generator *stitchableGenerator) {
		findInGenerator(generator, segType, idx).Split = split
	}
}

func WithCoreASes(cores ...string) StitchableMod {
	ASes := make([]addr.IA, len(cores))
	for i, core := range cores {
		ASes[i] = xtest.MustParseIA(core)
	}
	return func(generator *stitchableGenerator) {
		generator.cores = append(generator.cores, ASes...)
	}
}

// WithUpSegs is called like: WithUpSegs(2,2,3,6).
// meaning to create up segments to indices 2 (twice), 3 and 6.
// When using an index N in WithUpSegs(N), if N=0 it refers to the src, N=1 to dst,
// and N>1 to the (N-2)th core (e.g. N=5 refers to the 5-2= 3rd core AS).
// A default path of only two hops is created. To define the path yourself use
// the WithUpPaths function instead.
func WithUpSegs(idxs ...int) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, idx := range idxs {
			var dst addr.IA
			switch idx {
			case 0:
				panic("cannot link src to src")
			case 1:
				dst = generator.stitchable.DstIA
			default:
				dst = generator.cores[idx-2]
			}
			l := &colibri.ReservationLooks{
				SrcIA: generator.stitchable.SrcIA,
				DstIA: dst,
				Id:    generator.newUpID(),
				PathSteps: []base.PathStep{
					{Ingress: 0, IA: generator.stitchable.SrcIA, Egress: 1},
					{Ingress: 1, IA: dst, Egress: 0},
				},
			}
			generator.stitchable.Up = append(generator.stitchable.Up, l)
		}
	}
}

// WithDownSegs is called like: WithDownSegs(2,2,3,6).
// meaning to create down segments to indices 2 (twice), 3 and 6.
// When using an index N in WithDownSegs(N), if N=0 it refers to the src, N=1 to dst,
// and N>1 to the (N-2)th core (e.g. N=5 refers to the 5-2= 3rd core AS).
// A default path of only two hops is created. To define the path yourself use
// the WithDownPaths function instead.
func WithDownSegs(idxs ...int) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, idx := range idxs {
			var src addr.IA
			switch idx {
			case 0:
				src = generator.stitchable.SrcIA
			case 1:
				panic("cannot link dst to dst")
			default:
				src = generator.cores[idx-2]
			}
			l := &colibri.ReservationLooks{
				SrcIA: src,
				DstIA: generator.stitchable.DstIA,
				Id:    generator.newDownID(),
				PathSteps: []base.PathStep{
					{Ingress: 0, IA: src, Egress: 1},
					{Ingress: 1, IA: generator.stitchable.DstIA, Egress: 0},
				},
			}
			generator.stitchable.Down = append(generator.stitchable.Down, l)
		}
	}
}

type Pair [2]int

func P(src, dst int) Pair {
	return [2]int{src, dst}
}

// WithCoreSegs is called like:
// WithCoreSegs({2,3}, {3,2}, {3,4})
// indicating there are three links: 2->3 , 3->2 , and 3->4
// A default path of only two hops is created. To define the path yourself use
// the WithCorePaths function instead.
func WithCoreSegs(pairs ...[2]int) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, pair := range pairs {
			var src addr.IA
			switch pair[0] {
			case 0:
				src = generator.stitchable.SrcIA
			case 1:
				src = generator.stitchable.DstIA
			default:
				if pair[0]-2 > len(generator.cores) {
					panic(fmt.Errorf("bad index pair %v, not enough core ASes", pair))
				}
				src = generator.cores[pair[0]-2]
			}

			var dst addr.IA
			switch pair[1] {
			case 0:
				dst = generator.stitchable.SrcIA
			case 1:
				dst = generator.stitchable.DstIA
			default:
				if pair[1]-2 > len(generator.cores) {
					panic(fmt.Errorf("bad index pair %v, not enough core ASes", pair))
				}
				dst = generator.cores[pair[1]-2]
			}

			if src == dst {
				panic("src and dst are the same")
			}

			l := &colibri.ReservationLooks{
				SrcIA: src,
				DstIA: dst,
				Id:    generator.newCoreID(src),
				PathSteps: []base.PathStep{
					{Ingress: 0, IA: src, Egress: 1},
					{Ingress: 1, IA: dst, Egress: 0},
				},
			}
			generator.stitchable.Core = append(generator.stitchable.Core, l)
		}
	}
}

func WithUpPaths(stepsList ...base.PathSteps) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, steps := range stepsList {
			l := &colibri.ReservationLooks{
				SrcIA:     steps.SrcIA(),
				DstIA:     steps.DstIA(),
				Id:        generator.newUpID(),
				PathSteps: steps,
			}
			generator.stitchable.Up = append(generator.stitchable.Up, l)
		}
	}
}

func WithDownPaths(stepsList ...base.PathSteps) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, steps := range stepsList {
			l := &colibri.ReservationLooks{
				SrcIA:     steps.SrcIA(),
				DstIA:     steps.DstIA(),
				Id:        generator.newUpID(),
				PathSteps: steps,
			}
			generator.stitchable.Down = append(generator.stitchable.Down, l)
		}
	}
}

func WithCorePaths(stepsList ...base.PathSteps) StitchableMod {
	return func(generator *stitchableGenerator) {
		for _, steps := range stepsList {
			l := &colibri.ReservationLooks{
				SrcIA:     steps.SrcIA(),
				DstIA:     steps.DstIA(),
				Id:        generator.newUpID(),
				PathSteps: steps,
			}
			generator.stitchable.Core = append(generator.stitchable.Core, l)
		}
	}
}

// FullTrip generator and mods:

type fullTripGenerator struct {
	trips                      []*colibri.FullTrip
	src                        addr.IA
	dst                        addr.IA
	cores                      []addr.IA
	lastup, lastcore, lastdown int
}

func (g *fullTripGenerator) GetAI(idx int) addr.IA {
	switch idx {
	case 0:
		return g.src
	case 1:
		return g.dst
	default:
		if len(g.cores) < idx-1 {
			panic(fmt.Sprintf("bad index for core AS %d: only %d cores defined", idx, len(g.cores)))
		}
		return g.cores[idx-2]
	}
}

func (g *fullTripGenerator) newSeg(segType segTypeSelector,
	srcIdx, dstIdx int) *colibri.ReservationLooks {

	src := g.GetAI(srcIdx)
	dst := g.GetAI(dstIdx)
	steps := []base.PathStep{
		{Ingress: 0, IA: src, Egress: 1},
		{Ingress: 1, IA: dst, Egress: 0},
	}
	return g.newSegWithPath(segType, steps)
}

func (g *fullTripGenerator) newSegWithPath(segType segTypeSelector,
	steps base.PathSteps) *colibri.ReservationLooks {

	var id reservation.ID
	switch segType {
	case Up:
		id = g.newUpID()
	case Core:
		id = g.newCoreID(steps.SrcIA())
	case Down:
		id = g.newDownID()
	}
	return &colibri.ReservationLooks{
		SrcIA:     steps.SrcIA(),
		DstIA:     steps.DstIA(),
		Id:        id,
		PathSteps: steps,
	}
}

func (g *fullTripGenerator) newUpID() reservation.ID {
	g.lastup++
	id := reservation.ID{
		ASID: g.src.AS(),
	}
	id.SetSegmentSuffix(g.lastup)
	return id
}

func (g *fullTripGenerator) newDownID() reservation.ID {
	g.lastdown++
	id := reservation.ID{
		ASID: g.dst.AS(),
	}
	id.SetSegmentSuffix(g.lastdown)
	return id
}

func (g *fullTripGenerator) newCoreID(asid addr.IA) reservation.ID {
	g.lastcore++
	id := reservation.ID{
		ASID: asid.AS(),
	}
	id.SetSegmentSuffix(g.lastcore)
	return id
}

type FullTripMod func(*fullTripGenerator)

func NewFullTrips(src, dst string, mods ...FullTripMod) []*colibri.FullTrip {
	t := &fullTripGenerator{
		src: xtest.MustParseIA(src),
		dst: xtest.MustParseIA(dst),
	}
	for _, mod := range mods {
		mod(t)
	}
	return t.trips
}

func WithCoresInTrip(cores ...string) FullTripMod {
	IAs := make([]addr.IA, len(cores))
	for i, core := range cores {
		IAs[i] = xtest.MustParseIA(core)
	}
	return func(generator *fullTripGenerator) {
		generator.cores = append(generator.cores, IAs...)
	}
}

type UType Pair
type CType Pair
type DType Pair

func U(a, b int) UType {
	return UType{a, b}
}

func C(a, b int) CType {
	return CType{a, b}
}

func D(a, b int) DType {
	return DType{a, b}
}

type trip interface {
	is_a_trip()
}

func (UType) is_a_trip() {}
func (CType) is_a_trip() {}
func (DType) is_a_trip() {}

// T constructs a trip slice
func T(trips ...trip) []trip {
	return trips
}

// WithTrips is called like:
// WithTrips(T(U(0,1)), T(U(0,2), D(2,1)) )
// indicating that there are two trips, one up src->dst and another up,down src->core1,core1->dst
func WithTrips(trips ...[]trip) FullTripMod {
	return func(generator *fullTripGenerator) {
		for _, fulltrip := range trips { // each fulltrip came from a call to T(...)
			newtrip := make(colibri.FullTrip, 0, len(fulltrip))
			for _, trip := range fulltrip {
				switch t := trip.(type) {
				case UType:
					newtrip = append(newtrip, generator.newSeg(Up, t[0], t[1]))
				case CType:
					newtrip = append(newtrip, generator.newSeg(Core, t[0], t[1]))
				case DType:
					newtrip = append(newtrip, generator.newSeg(Down, t[0], t[1]))
				}
			}
			generator.trips = append(generator.trips, &newtrip)
		}
	}
}

// WithTripFromPaths builds a FullTrip from the received paths.
// It is called like:
// WithTripFromPaths(Up,0,"0:0:111",1,1,"0:0:110",0, Down,0,"0:1:110",2,1,"0:1:112",0)
// to create a FullTrip consisting on one up segment + one down segment.
func WithTripFromPaths(args ...interface{}) FullTripMod {
	var upseg, coreseg, downseg base.PathSteps
	remainingArgs := args
	for len(remainingArgs) > 0 {
		if t, ok := remainingArgs[0].(segTypeSelector); ok {
			var destinationSegment *base.PathSteps
			switch t {
			case Up:
				if upseg != nil {
					panic("only one up segment allowed")
				}
				destinationSegment = &upseg
			case Core:
				if coreseg != nil {
					panic("only one core segment allowed")
				}
				destinationSegment = &coreseg
			case Down:
				if downseg != nil {
					panic("only one down segment allowed")
				}
				destinationSegment = &downseg
			}
			pathArgs := []interface{}{}
			i := 1
			for ; i < len(remainingArgs); i += 3 {
				if _, ok := remainingArgs[i].(segTypeSelector); ok {
					break
				}
				if len(remainingArgs) < 3 {
					panic("bad arguments: path consists of steps of 3 arguments")
				}
				pathArgs = append(pathArgs,
					remainingArgs[i], remainingArgs[i+1], remainingArgs[i+2])
			}
			*destinationSegment = rt.NewSteps(pathArgs...) // will panic if bad args
			remainingArgs = remainingArgs[i:]
		} else {
			panic(fmt.Sprintf(`bad argument "%v"; should be Up,Core or Down`, remainingArgs[0]))
		}
	}
	return func(generator *fullTripGenerator) {
		ft := make(colibri.FullTrip, 0)
		if upseg != nil {
			ft = append(ft, generator.newSegWithPath(Up, upseg))
		}
		if coreseg != nil {
			ft = append(ft, generator.newSegWithPath(Core, coreseg))
		}
		if downseg != nil {
			ft = append(ft, generator.newSegWithPath(Down, downseg))
		}
		generator.trips = append(generator.trips, &ft)
	}
}

func findInGenerator(generator *stitchableGenerator, segType segTypeSelector,
	idx int) *colibri.ReservationLooks {

	switch segType {
	case Up:
		return generator.stitchable.Up[idx]
	case Core:
		return generator.stitchable.Core[idx]
	case Down:
		return generator.stitchable.Down[idx]
	}
	panic("bad parameters in test")
}
