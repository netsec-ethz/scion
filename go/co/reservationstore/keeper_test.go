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

package reservationstore

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/co/reservation"
	seg "github.com/scionproto/scion/go/co/reservation/segment"
	st "github.com/scionproto/scion/go/co/reservation/segmenttest"
	te "github.com/scionproto/scion/go/co/reservation/test"
	mockmanager "github.com/scionproto/scion/go/co/reservationstore/mock_reservationstore"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/pathpol"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestKeepOneShot(t *testing.T) {
	allPaths := map[addr.IA][]snet.Path{
		xtest.MustParseIA("1-ff00:0:2"): {
			te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"), // direct
			te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"), // direct
			te.NewSnetPath("1-ff00:0:1", 3, 88, "1-ff00:0:88", 99, 4, "1-ff00:0:2"),
		},
		xtest.MustParseIA("1-ff00:0:3"): {
			te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:3"), // direct
			te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:3"), // direct
			te.NewSnetPath("1-ff00:0:1", 3, 88, "1-ff00:0:88", 99, 4, "1-ff00:0:3"),
		},
	}
	now := util.SecsToTime(10)
	tomorrow := now.AddDate(0, 0, 1)
	c1 := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:2"),
		predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
		minBW:     10,
		maxBW:     42,
		splitCls:  2,
		endProps:  reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
	}
	c2 := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:3"),
		predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:3"), // direct
		minBW:     10,
		maxBW:     42,
		splitCls:  2,
		endProps:  reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
	}
	c2_notDirect := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:3"),
		predicate: newSequence(t, "1-ff00:0:1 0-0 1-ff00:0:3"), // not direct
		minBW:     10,
		maxBW:     42,
		splitCls:  2,
		endProps:  reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
	}
	c3 := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:4"),
		predicate: newSequence(t, "1-ff00:0:1 0-0 1-ff00:0:4"),
		minBW:     10,
		maxBW:     42,
		splitCls:  2,
		endProps:  reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
	}
	r1 := st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
		st.AddIndex(0, st.WithBW(12, 42, 0),
			st.WithExpiration(tomorrow)),
		st.AddIndex(1, st.WithBW(12, 24, 0),
			st.WithExpiration(tomorrow.Add(24*time.Hour))),
		st.ConfirmAllIndices(),
		st.WithActiveIndex(0),
		st.WithTrafficSplit(2),
		st.WithEndProps(reservation.StartLocal|reservation.EndLocal|reservation.EndTransfer))
	r2 := st.ModRsv(cloneR(r1), st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3"))
	r3 := st.ModRsv(cloneR(r1), st.WithPath("1-ff00:0:1", 1, 8, "1-ff00:0:2", 9, 1, "1-ff00:0:4"),
		st.WithNoActiveIndex())
	cases := map[string]struct {
		config              []*configuration
		reservations        []*seg.Reservation
		paths               map[addr.IA][]snet.Path
		expectedNewRequests int
		expectedWakeupTime  time.Time
		expectError         bool
	}{
		"simple": {
			config:              []*configuration{c1},
			paths:               allPaths,
			reservations:        []*seg.Reservation{r1},
			expectedNewRequests: 0,
			expectedWakeupTime:  now.Add(sleepAtMost),
		},
		"regular": {
			config: []*configuration{c1, c2},
			paths:  allPaths,
			reservations: []*seg.Reservation{
				cloneR(r1),
				cloneR(r2),
			},
			expectedNewRequests: 0,
			expectedWakeupTime:  now.Add(sleepAtMost),
		},
		"missing1": {
			config: []*configuration{c1, c2_notDirect},
			paths:  allPaths,
			reservations: []*seg.Reservation{
				cloneR(r1),
				cloneR(r2),
			},
			expectedNewRequests: 1,
			expectedWakeupTime:  now.Add(sleepAtMost),
		},
		"missing_all": {
			config:              []*configuration{c1, c2, c2_notDirect},
			paths:               allPaths,
			reservations:        []*seg.Reservation{},
			expectedNewRequests: 3,
			expectedWakeupTime:  now.Add(sleepAtMost),
		},
		"not_active": {
			config:              []*configuration{c3},
			paths:               allPaths,
			reservations:        []*seg.Reservation{r3},
			expectedNewRequests: 0,
			expectedWakeupTime:  now.Add(sleepAtMost),
		},
		"no_paths": {
			config:              []*configuration{c1, c2, c2_notDirect, c3},
			paths:               nil,
			reservations:        []*seg.Reservation{},
			expectedNewRequests: 0,
			expectedWakeupTime:  now.Add(sleepAtLeast),
			expectError:         true,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			localIA := xtest.MustParseIA("1-ff00:0:1")

			manager := mockmanager.NewMockServiceFacilitator(ctrl)
			entries := matchRsvsWithConfiguration(tc.reservations, tc.config)
			keeper := keeper{
				now: func() time.Time {
					return now
				},
				localIA:  localIA,
				provider: manager,
				entries:  entries,
			}
			manager.EXPECT().PathsTo(gomock.Any(),
				gomock.Any()).AnyTimes().DoAndReturn(
				func(_ context.Context, dstIA addr.IA) ([]snet.Path, error) {
					return tc.paths[dstIA], nil
				})
			manager.EXPECT().SetupRequest(gomock.Any(), gomock.Any()).
				Times(tc.expectedNewRequests).DoAndReturn(
				func(_ context.Context, req *seg.SetupReq) error {
					req.Reservation = &seg.Reservation{
						Indices: seg.Indices{
							{
								Idx:        0,
								Expiration: tomorrow,
								MinBW:      10,
								MaxBW:      42,
							},
						},
					}
					err := req.Reservation.SetIndexConfirmed(0)
					require.NoError(t, err)
					return nil
				})
			manager.EXPECT().ActivateRequest(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(_ context.Context, req *base.Request, steps base.PathSteps,
					path *colpath.ColibriPathMinimal, inReverse bool) error {

					return nil
				})

			wakeupTime, err := keeper.OneShot(ctx)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedWakeupTime, wakeupTime)
		})
	}
}

func TestRequirementsCompliance(t *testing.T) {
	now := util.SecsToTime(0)
	tomorrow := now.Add(3600 * 24 * time.Second)
	reqs := &configuration{
		pathType:  reservation.UpPath,
		predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
		minBW:     10,
		maxBW:     42,
		splitCls:  2,
		endProps:  reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
	}
	cases := map[string]struct {
		conf               *configuration
		rsv                *seg.Reservation
		atLeastUntil       time.Time
		expectedCompliance Compliance
	}{
		"compliant, one index": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithPathType(reservation.UpPath),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: Compliant,
		},
		"one non compliant index, minbw": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.AddIndex(0, st.WithBW(1, 24, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
		"one non compliant index, maxbw": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.AddIndex(0, st.WithBW(12, 44, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
		"one non compliant index, expired": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(now)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
		"no active indices": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.ConfirmAllIndices(),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsActivation,
		},
		"no indices": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
		"compliant in the past, not now": {
			conf: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.AddIndex(1, st.WithBW(1, 24, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(1), // will destroy index 0
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := &entry{
				conf: tc.conf,
				rsv:  tc.rsv,
			}
			c := compliance(entry, tc.atLeastUntil)
			require.Equal(t, tc.expectedCompliance, c,
				"expected %s got %s", tc.expectedCompliance, c)
		})
	}
}

func TestMatchRsvsWithConfiguration(t *testing.T) {
	r1 := st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
		st.WithPathType(reservation.UpPath),
		st.WithTrafficSplit(1), // 1
		st.WithEndProps(reservation.StartLocal))
	r2 := st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
		st.WithPathType(reservation.UpPath),
		st.WithTrafficSplit(2), // 2
		st.WithEndProps(reservation.StartLocal))
	c1 := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:2"),
		pathType:  reservation.UpPath,
		predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"),
		splitCls:  1,
		endProps:  reservation.StartLocal,
	}
	c2 := &configuration{
		dst:       xtest.MustParseIA("1-ff00:0:2"),
		pathType:  reservation.UpPath,
		predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"),
		splitCls:  2,
		endProps:  reservation.StartLocal,
	}
	c1_copy := func() *configuration { a := *c1; return &a }()
	cases := map[string]struct {
		rsvs              []*seg.Reservation
		confs             []*configuration
		expectedConfToRsv []int // configuration i paired with rsvs[ expected[i] ]
	}{
		"both": {
			rsvs:              []*seg.Reservation{r1, r2},
			confs:             []*configuration{c1, c2},
			expectedConfToRsv: []int{0, 1},
		},
		"unordered": {
			rsvs:              []*seg.Reservation{r1, r2},
			confs:             []*configuration{c2, c1},
			expectedConfToRsv: []int{1, 0},
		},
		"only_one": {
			rsvs:              []*seg.Reservation{r2},
			confs:             []*configuration{c1, c2},
			expectedConfToRsv: []int{-1, 0},
		},
		"none": {
			rsvs:              []*seg.Reservation{},
			confs:             []*configuration{c2, c1},
			expectedConfToRsv: []int{-1, -1},
		},
		"same_config": {
			rsvs:              []*seg.Reservation{r1, r2},
			confs:             []*configuration{c1, c1_copy},
			expectedConfToRsv: []int{0, -1},
		},
		"no_config": {
			rsvs:              []*seg.Reservation{r1, r2},
			confs:             []*configuration{},
			expectedConfToRsv: []int{},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			// check that the test case is well formed
			require.Equal(t, len(tc.confs), len(tc.expectedConfToRsv),
				"wrong use case: expected matches must have the same length as confs")

			entries := matchRsvsWithConfiguration(tc.rsvs, tc.confs)
			require.Len(t, entries, len(tc.confs))

			confToReservation := make(map[*configuration]*seg.Reservation)
			for i, e := range tc.expectedConfToRsv {
				var r *seg.Reservation
				if e >= 0 {
					r = tc.rsvs[e]
				}
				_, ok := confToReservation[tc.confs[i]]
				require.False(t, ok)
				confToReservation[tc.confs[i]] = r
			}
			for i, e := range entries {
				require.Contains(t, confToReservation, e.conf)
				require.Same(t, confToReservation[e.conf], e.rsv,
					"entry %d has unexpected reservation", i)
				delete(confToReservation, e.conf)
			}
		})
	}
}

func TestFindCompatibleConfiguration(t *testing.T) {
	cases := map[string]struct {
		rsv      *seg.Reservation
		confs    []*configuration
		expected int // index of match on `confs`, or -1
	}{
		"ok": {
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reservation.StartLocal)),
			confs: []*configuration{
				{
					dst:       xtest.MustParseIA("1-ff00:0:2"),
					pathType:  reservation.UpPath,
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps:  reservation.StartLocal,
				},
			},
			expected: 0,
		},
		"bad_path_type": {
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.DownPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reservation.StartLocal)),
			confs: []*configuration{
				{
					dst:       xtest.MustParseIA("1-ff00:0:2"),
					pathType:  reservation.UpPath,
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps:  reservation.StartLocal,
				},
			},
			expected: -1,
		},
		"bad_traffic_split": {
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(1),
				st.WithEndProps(reservation.StartLocal)),
			confs: []*configuration{
				{
					dst:       xtest.MustParseIA("1-ff00:0:2"),
					pathType:  reservation.UpPath,
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps:  reservation.StartLocal,
				},
			},
			expected: -1,
		},
		"bad_end_props": {
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reservation.StartLocal)),
			confs: []*configuration{
				{
					dst:       xtest.MustParseIA("1-ff00:0:2"),
					pathType:  reservation.UpPath,
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps:  reservation.StartLocal | reservation.EndLocal,
				},
			},
			expected: -1,
		},
		"bad_path": {
			rsv: st.NewRsv(st.WithPath("1-ff00:0:11", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reservation.StartLocal)),
			confs: []*configuration{
				{
					dst:       xtest.MustParseIA("1-ff00:0:2"),
					pathType:  reservation.UpPath,
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps:  reservation.StartLocal,
				},
			},
			expected: -1,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			i := findCompatibleConfiguration(tc.rsv, tc.confs)
			require.Equal(t, tc.expected, i)
		})
	}
}

func newSequence(t *testing.T, str string) *pathpol.Sequence {
	t.Helper()
	seq, err := pathpol.NewSequence(str)
	xtest.FailOnErr(t, err)
	return seq
}

func cloneR(r *seg.Reservation) *seg.Reservation {
	c := *r
	return &c
}
