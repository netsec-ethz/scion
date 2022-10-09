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

package sorting

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	rt "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri"
	ct "github.com/scionproto/scion/go/lib/colibri/coltest"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

func TestByBW(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1, 1, 1),              // three up segments
		ct.WithBW(ct.Up, 0, ct.Allocbw, 11), // idx 0
		ct.WithSplit(ct.Up, 0, 7),
		ct.WithBW(ct.Up, 1, ct.Allocbw, 12), // idx 1
		ct.WithSplit(ct.Up, 1, 7),
		ct.WithBW(ct.Up, 2, ct.Allocbw, 11), // idx 2
		ct.WithSplit(ct.Up, 2, 3),
	)

	trips := colibri.CombineAll(stitchables)
	require.Len(t, trips, 3)
	sort.SliceStable(trips, indexSort(trips, ByBW))

	require.Equal(t, bw(12, 7), trips[0].BW())
	require.Equal(t, bw(11, 7), trips[1].BW())
	require.Equal(t, bw(11, 3), trips[2].BW())
}

func TestByNumberOfASes(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpPaths(rt.NewSteps(0, "1-ff00:0:111", 1, 2, "1-ff00:0:112", 0),
			rt.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 0)),

		ct.WithDownPaths(rt.NewSteps(0, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0)),
	)

	trips := colibri.CombineAll(stitchables)
	require.Len(t, trips, 2)
	sort.SliceStable(trips, indexSort(trips, ByNumberOfASes))
	require.Equal(t, 2, trips[0].NumberOfASes())
	require.Equal(t, 3, trips[1].NumberOfASes())
}

func TestByMinBW(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1, 1),
		ct.WithBW(ct.Up, 0, ct.Minbw, 1),
		ct.WithBW(ct.Up, 1, ct.Minbw, 2),
	)

	trips := colibri.CombineAll(stitchables)
	require.Len(t, trips, 2)
	sort.SliceStable(trips, indexSort(trips, ByMinBW))
	require.Equal(t, reservation.BWCls(2), trips[0].MinBW())
	require.Equal(t, reservation.BWCls(1), trips[1].MinBW())
	// reverse order
	sort.SliceStable(trips, indexSort(trips, func(a, b colibri.FullTrip) bool {
		return !ByMinBW(a, b)
	}))
	require.Equal(t, reservation.BWCls(1), trips[0].MinBW())
	require.Equal(t, reservation.BWCls(2), trips[1].MinBW())
	// also reverse order
	sort.SliceStable(trips, indexSort(trips, Inverse(ByMinBW)))
	require.Equal(t, reservation.BWCls(1), trips[0].MinBW())
	require.Equal(t, reservation.BWCls(2), trips[1].MinBW())
}

func TestByMaxBW(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1, 1),
		ct.WithBW(ct.Up, 0, ct.Maxbw, 11),
		ct.WithBW(ct.Up, 1, ct.Maxbw, 12),
	)

	trips := colibri.CombineAll(stitchables)
	require.Len(t, trips, 2)
	sort.SliceStable(trips, indexSort(trips, ByMaxBW))
	require.Equal(t, reservation.BWCls(12), trips[0].MaxBW())
	require.Equal(t, reservation.BWCls(11), trips[1].MaxBW())
}

func TestByAllocBW(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1, 1),
		ct.WithBW(ct.Up, 0, ct.Allocbw, 11),
		ct.WithBW(ct.Up, 1, ct.Allocbw, 12),
	)

	trips := colibri.CombineAll(stitchables)
	require.Len(t, trips, 2)
	sort.SliceStable(trips, indexSort(trips, ByAllocBW))
	require.Equal(t, reservation.BWCls(12), trips[0].AllocBW())
	require.Equal(t, reservation.BWCls(11), trips[1].AllocBW())
}

func indexSort(trips []*colibri.FullTrip,
	orderFcn func(a, b colibri.FullTrip) bool) func(i, j int) bool {

	t := trips
	return func(i, j int) bool {
		a, b := t[i], t[j]
		return orderFcn(*a, *b)
	}
}

func bw(bwCls reservation.BWCls, splitCls reservation.SplitCls) uint64 {
	return uint64(float64(bwCls.ToKbps()) * splitCls.SplitForData())
}
