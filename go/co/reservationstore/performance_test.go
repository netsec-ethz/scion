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

package reservationstore_test

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/co/reservation/sqlite"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/co/reservationstore"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	collayer "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/xtest"
)

const REPS = 100

func TestStore(t *testing.T) {
	var s reservationstorage.Store = &reservationstore.Store{}
	_ = s
}

func TestDebugAdmitSegmentReservation(t *testing.T) {
	// TODO(juagargi) enable the tests again
	// // run for 1 distinct source AS:
	// timeAdmitSegmentReservationManyRsvsSameAS(t, 1)
	// // and with a different balance, for 100 distinct source ASes:
	// timeAdmitSegmentReservationManySourceASes(t, 10)
}

func TestDebugAdmitE2EReservation(t *testing.T) {
	// timeAdmitE2EReservationManyEndhosts(t, 1)
	// timeAdmitE2EReservationManySegments(t, 1)
}

// TestComputeMAC tests that the MAC computation functions in the BR and the store are consistent.
func TestComputeMAC(t *testing.T) {
	privateKeyBytes := xtest.MustParseHexString("5b56986be02a37d30110c854b5f25959")
	privateKey, err := libcolibri.InitColibriKey(privateKeyBytes)
	require.NoError(t, err)
	srcAS := xtest.MustParseAS("ff00:0:111")
	dstAS := xtest.MustParseAS("ff00:0:112")

	cases := map[string]struct {
		inf      collayer.InfoField  // used to compute MAC in the BR
		hfs      []collayer.HopField // used in the BR and the store
		pathType reservation.PathType
	}{
		"segment first hopfield": {
			inf: collayer.InfoField{
				S:           true,
				R:           false,
				C:           true,
				Ver:         1,
				CurrHF:      0,
				ResIdSuffix: xtest.MustParseHexString("000000000000000000000001"),
				BwCls:       9,
				Rlc:         7,
				OrigPayLen:  1234,
				HFCount:     2,
				ExpTick:     1122334455,
			},
			hfs: []collayer.HopField{
				{IngressId: 0, EgressId: 41},
				{},
			},
			pathType: reservation.UpPath,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var macBR [4]byte
			err := libcolibri.MACStatic(macBR[:], privateKey, &tc.inf,
				&tc.hfs[tc.inf.CurrHF], srcAS, dstAS)
			require.NoError(t, err)

			store := &reservationstore.Store{}
			store.SetColibriKey(privateKeyBytes)
			tok := &reservation.Token{
				InfoField: reservation.InfoField{
					PathType:       tc.pathType,
					Idx:            reservation.IndexNumber(tc.inf.Ver),
					ExpirationTick: reservation.Tick(tc.inf.ExpTick),
					BWCls:          reservation.BWCls(tc.inf.BwCls),
					RLC:            reservation.RLC(tc.inf.Rlc),
				},
				HopFields: make([]reservation.HopField, len(tc.hfs)-1),
			}
			hf := tc.hfs[tc.inf.CurrHF]
			err = store.ComputeMAC(tc.inf.ResIdSuffix, tok, srcAS, 0, hf.IngressId, hf.EgressId)
			require.NoError(t, err)
			require.Equal(t, macBR[:], tok.HopFields[0].Mac[:])
		})
	}
}

type performanceTestCase struct {
	TestName string
	X        []int
	Xlabel   string
	YLabels  []string // leave empty to generate default "sample 1", "sample 2", ...

	Repetitions int
	Function    func(*testing.T, int) time.Duration
	Filter      func(*testing.T, []time.Duration) []time.Duration

	DebugPrintProgress bool
	DebugSkipExec      bool
}

// TestPerformanceCOLIBRI runs a performance test, writing the time values in CSV files.
// The test is time consuming, and it is only performed if the environment variable
// COLIBRI_PERF_TESTS is defined.
func TestPerformanceCOLIBRI(t *testing.T) {

	if os.Getenv("COLIBRI_PERF_TESTS") == "" {
		t.SkipNow()
	}

	testCases := []performanceTestCase{
		{
			TestName:           "segmentAdmitManyRsvsSameAS",
			X:                  delta(1, 1000, 10),
			Xlabel:             "# ASes",
			Repetitions:        REPS,
			Function:           timeAdmitSegmentReservationManyRsvsSameAS,
			Filter:             identity,
			DebugPrintProgress: true,
			DebugSkipExec:      true,
		},
		//////////////
		//    Segment
		//////////////
		{
			TestName: "segmentAdmission_0_percent",
			X:        delta(0, 10000, 2000),
			Xlabel:   "# Other ASes",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				ratio := 0.0
				sameSourceASID := int(float64(count) * ratio / 100.0)
				differentSrcASesCount := count - sameSourceASID
				return timeAdmitSegmentReservationTwoDimensions(t,
					sameSourceASID, differentSrcASesCount)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
		{
			TestName: "segmentAdmission_10_percent",
			X:        delta(0, 10000, 2000),
			Xlabel:   "# Other ASes",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				ratio := 10.0
				sameSourceASID := int(float64(count) * ratio / 100.0)
				differentSrcASesCount := count - sameSourceASID
				return timeAdmitSegmentReservationTwoDimensions(t,
					sameSourceASID, differentSrcASesCount)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
		{
			TestName: "segmentAdmission_50_percent",
			X:        delta(0, 10000, 2000),
			Xlabel:   "# Other ASes",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				ratio := 50.0
				sameSourceASID := int(float64(count) * ratio / 100.0)
				differentSrcASesCount := count - sameSourceASID
				return timeAdmitSegmentReservationTwoDimensions(t,
					sameSourceASID, differentSrcASesCount)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
		{
			TestName: "segmentAdmission_90_percent",
			X:        delta(0, 10000, 2000),
			Xlabel:   "# Other ASes",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				ratio := 90.0
				sameSourceASID := int(float64(count) * ratio / 100.0)
				differentSrcASesCount := count - sameSourceASID
				return timeAdmitSegmentReservationTwoDimensions(t,
					sameSourceASID, differentSrcASesCount)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},

		///////////////////////
		//   E2E
		///////////////////////
		{
			TestName: "e2eAdmit_1",
			X:        []int{0, 10, 100, 1000, 10000, 100000},
			Xlabel:   "# endhosts",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				existingSegments := 1
				return timeAdmitE2EReservationTwoDimensions(t, existingSegments, count)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
		{
			TestName: "e2eAdmit_5000",
			X:        []int{0, 10, 100, 1000, 10000, 100000},
			Xlabel:   "# endhosts",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				existingSegments := 5000
				return timeAdmitE2EReservationTwoDimensions(t, existingSegments, count)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
		{
			TestName: "e2eAdmit_10000",
			X:        []int{0, 10, 100, 1000, 10000, 100000},
			Xlabel:   "# endhosts",
			// YLabels:     []string{"ave. µsecs"},
			Repetitions: REPS,
			Function: func(t *testing.T, count int) time.Duration {
				existingSegments := 10000
				return timeAdmitE2EReservationTwoDimensions(t, existingSegments, count)
			},
			Filter:             identity,
			DebugPrintProgress: true,
		},
	}
	for _, tc := range testCases {
		if tc.DebugSkipExec {
			continue
		}
		tc := tc
		t.Run(tc.TestName, func(t *testing.T) {
			t.Parallel()
			doPerformanceTest(t, tc)
		})
	}
}

func doPerformanceTest(t *testing.T, tc performanceTestCase) {
	values := mapWithFunction(t,
		repeatWithFilter(t, tc.Function, tc.Repetitions, tc.Filter), tc.X, tc.DebugPrintProgress)
	var columnTitles []string
	if len(tc.YLabels) > 0 {
		columnTitles = append([]string{tc.Xlabel}, tc.YLabels...)
	} else {
		columnTitles = make([]string, tc.Repetitions+1)
		columnTitles[0] = tc.Xlabel
		for i := 0; i < len(values[0]); i++ {
			columnTitles[i+1] = fmt.Sprintf("sample %d", i)
		}
	}
	toCSV(t, fmt.Sprintf("%s.csv", tc.TestName), columnTitles, tc.X, values)
}

/////////////////////////////////////////

func delta(first, last, stride int) []int {
	ret := make([]int, (last-first)/stride+1)
	for i, j := first, 0; i <= last; i += stride {
		ret[j] = i
		j++
	}
	return ret
}

func mapWithFunction(t *testing.T,
	fn func(*testing.T, int) []time.Duration,
	xValues []int,
	printProgress bool) [][]time.Duration {

	values := make([][]time.Duration, len(xValues))
	// TODO worker pool here. Monothreaded it takes 21.8s to process 1-100 e2e
	for i, x := range xValues {
		row := fn(t, x)
		values[i] = row
		if printProgress {
			t.Logf("[%v] done X = %v\n", time.Now().Format(time.StampMilli), x)
		}
	}
	return values
}

type filterfunc func(*testing.T, []time.Duration) []time.Duration

// returns a function applicable to map
func repeatWithFilter(t *testing.T,
	sampler func(*testing.T, int) time.Duration,
	repeatCount int,
	filter filterfunc) func(*testing.T, int) []time.Duration {

	ret := func(t *testing.T, x int) []time.Duration {
		samples := make([]time.Duration, repeatCount)
		// TODO worker pool here
		for i := 0; i < repeatCount; i++ {
			samples[i] = sampler(t, x)
		}
		return filter(t, samples)
	}
	return ret
}

func identity(t *testing.T, values []time.Duration) []time.Duration {
	return values
}

// values contains N repetitions of scalars. Returns just 1 value in the slice.
func getAverage(t *testing.T, values []time.Duration) []time.Duration {
	require.Greater(t, len(values), 0)

	average := time.Duration(0)
	for i := 0; i < len(values); i++ {
		average += values[i]
	}
	average = time.Duration(average.Nanoseconds() / int64(len(values)))
	return []time.Duration{average}
}

// returns Q1, median, Q3 per dimension (three values in the slice).
func getQuartiles(t *testing.T, values []time.Duration) []time.Duration {
	medianFun := func(values []time.Duration) time.Duration {
		require.Greater(t, len(values), 0)
		l := len(values) / 2
		if len(values)%2 == 1 {
			return values[l]
		} else {
			return (values[l-1] + values[l]) / 2
		}
	}
	// sort in place
	sort.Slice(values, func(i, j int) bool {
		return values[i] < values[j]
	})
	median := medianFun(values)
	var a, b int // indices for Q1 and Q3 segments
	l := len(values) / 2
	if len(values)%2 == 1 {
		a = l
		b = l + 1
	} else {
		a = l - 1
		b = l + 1
	}
	q1 := medianFun(values[:a])
	q3 := medianFun(values[b:])
	return []time.Duration{q1, median, q3}
}

func toCSV(t *testing.T, filename string, columnTitles []string,
	xValues []int, values [][]time.Duration) {

	width := len(values[0]) + 1
	require.Equal(t, len(xValues), len(values))
	require.Equal(t, len(columnTitles), width)

	f, err := os.Create(filename)
	require.NoError(t, err)
	defer f.Close()

	w := csv.NewWriter(f)
	err = w.Write(columnTitles)
	require.NoError(t, err)
	for i := 0; i < len(values); i++ {
		require.Equal(t, len(values[i]), width-1, "failed at row %d", i)
		row := make([]string, width)
		row[0] = fmt.Sprintf("%d", xValues[i])
		for j := 1; j < width; j++ {
			row[j] = fmt.Sprintf("%d", values[i][j-1].Microseconds())
		}
		w.Write(row)
	}
	w.Flush()
}

///////////////////////////////////////////////////////////
////////////////////////// benchmarks

func BenchmarkAdmitSegmentReservation10(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 10)
}

func BenchmarkAdmitSegmentReservation100(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 100)
}

func BenchmarkAdmitSegmentReservation1000(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 1000)
}

func BenchmarkAdmitSegmentReservation5000(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 5000)
}

func BenchmarkAdmitSegmentReservation10000(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 10000)
}

func BenchmarkAdmitSegmentReservation100000(b *testing.B) {
	benchmarkAdmitSegmentReservation(b, 100000)
}

func benchmarkAdmitSegmentReservation(b *testing.B, count int) {
	// db := newDB(b)
	// defer db.Close()

	// cap := newCapacities()
	// admitter := newStatefulAdmitter(cap)
	// s := reservationstore.NewStore(xtest.MustParseIA("1-1"), db, admitter, nil)

	// AddSegmentReservation(b, db, "ff00:1:1", count)
	// ctx := context.Background()

	// b.ResetTimer()
	// for n := 0; n < b.N; n++ {
	// 	req := newTestSegmentRequest(b, "ff00:1:111", 1, 2, 5, 7)
	// 	trace.WithRegion(ctx, "AdmitSegmentReservation", func() {
	// 		_, err := s.AdmitSegmentReservation(ctx, req)
	// 		require.NoError(b, err, "iteration n = %d", n)
	// 	})
	// }
}

///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

func timeAdmitSegmentReservationManyRsvsSameAS(t *testing.T, count int) time.Duration {
	return timeAdmitSegmentReservationTwoDimensions(t, count, 1)
}

func timeAdmitSegmentReservationManySourceASes(t *testing.T, count int) time.Duration {
	return timeAdmitSegmentReservationTwoDimensions(t, 1, count)
}

func timeAdmitSegmentReservationTwoDimensions(t *testing.T,
	sameSourceASIDCount, diverseASIDsCount int) time.Duration {

	// db := newDB(t)
	// defer db.Close()

	// cap := newCapacities()
	// admitter := newStatefulAdmitter(cap)
	// s := reservationstore.NewStore(xtest.MustParseIA("1-1"), db, admitter, nil)

	// thisASID := "ff00:10:111"
	// AddSegmentReservation(t, db, thisASID, sameSourceASIDCount)
	// for i := 0; i < diverseASIDsCount; i++ {
	// 	ID := xtest.MustParseAS("ff00:1:1")
	// 	ID += addr.AS(i)
	// 	AddSegmentReservation(t, db, ID.String(), 1)
	// }

	// ctx := context.Background()
	// req := newTestSegmentRequest(t, thisASID, 1, 2, 5, 7)
	// var err error
	// //
	// // profile here
	// //
	// // blockProfile, err := os.Create("admission_block-profile.pprof")
	// // require.NoError(t, err)
	// // runtime.SetBlockProfileRate(10)
	// //
	// // cpuProfile, err := os.Create("admission_cpu-profile.pprof")
	// // require.NoError(t, err)
	// // err = pprof.StartCPUProfile(cpuProfile)
	// // require.NoError(t, err)
	// //
	// //
	// t0 := time.Now()
	// _, err = s.AdmitSegmentReservation(ctx, req)
	// t1 := time.Since(t0)
	// require.NoError(t, err)
	// //
	// // pprof.StopCPUProfile()
	// // err = pprof.Lookup("block").WriteTo(blockProfile, 1)
	// // require.NoError(t, err)
	// //
	// return t1
	return time.Duration(0)
}

func timeAdmitE2EReservationManyEndhosts(t *testing.T, count int) time.Duration {
	return timeAdmitE2EReservationTwoDimensions(t, 1, count)
}

func timeAdmitE2EReservationManySegments(t *testing.T, count int) time.Duration {
	return timeAdmitE2EReservationTwoDimensions(t, count, 10)
}

func timeAdmitE2EReservationTwoDimensions(t *testing.T, countSegments, countE2E int) time.Duration {
	// db := newDB(t)
	// defer db.Close()
	// ctx := context.Background()

	// insertRsvInDB(t, db, "ff00:1:1", countSegments, countE2E)

	// // now perform the actual E2E admission
	// cap := newCapacities()
	// admitter := newStatefulAdmitter(cap)
	// s := reservationstore.NewStore(xtest.MustParseIA("1-1"), db, admitter, nil)

	// successfulReq := newTestE2ESuccessReq(t, "ff00:1:1")
	// t0 := time.Now()
	// _, err := s.AdmitE2EReservation(ctx, successfulReq)
	// t1 := time.Since(t0)
	// require.NoError(t, err)
	// return t1
	return time.Duration(0)
}

func insertRsvInDB(t testing.TB, db backend.DB, ASID string, countSegment, countE2E int) {
	ctx := context.Background()
	backend := db.(*sqlite.Backend)

	if countSegment > 0 {
		AddSegmentReservation(t, db, ASID, countSegment)
		c, err := backend.DebugCountSegmentRsvs(ctx)
		require.NoError(t, err)
		require.Equal(t, c, countSegment)
	}
	if countE2E > 0 {
		// add `count` E2E other segments in DB
		AddE2EReservation(t, db, ASID, countE2E)
		c, err := backend.DebugCountE2ERsvs(ctx)
		require.NoError(t, err)
		require.Equal(t, c, countE2E)
	}
}
