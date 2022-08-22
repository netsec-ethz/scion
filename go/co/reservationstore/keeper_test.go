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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/conf"
	"github.com/scionproto/scion/go/co/reservation/segment"
	st "github.com/scionproto/scion/go/co/reservation/segmenttest"
	te "github.com/scionproto/scion/go/co/reservation/test"
	mockmanager "github.com/scionproto/scion/go/co/reservationstore/mock_reservationstore"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/pathpol"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestKeepOneShotDeleteme(t *testing.T) {
	now := util.SecsToTime(10)
	tomorrow := now.AddDate(0, 0, 1)
	endProps1 := reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer
	cases := map[string]struct {
		destinations          map[addr.IA][]requirementsDeleteme
		paths                 map[addr.IA][]snet.Path
		reservations          map[addr.IA][]*segment.Reservation
		expectedRequestsCalls int
		expectedWakeupTime    time.Time
	}{
		"regular": {
			destinations: map[addr.IA][]requirementsDeleteme{
				xtest.MustParseIA("1-ff00:0:2"): {{
					predicate:     newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:         10,
					maxBW:         42,
					splitCls:      2,
					endProps:      endProps1,
					minActiveRsvs: 1,
				}, {
					predicate:     newSequence(t, "1-ff00:0:1 0+ 1-ff00:0:2"), // not direct
					minBW:         10,
					maxBW:         42,
					splitCls:      2,
					endProps:      endProps1,
					minActiveRsvs: 1,
				}},
				xtest.MustParseIA("1-ff00:0:3"): {{
					predicate:     newSequence(t, "1-ff00:0:1 1-ff00:0:3"), // direct
					minBW:         10,
					maxBW:         42,
					splitCls:      2,
					endProps:      endProps1,
					minActiveRsvs: 1,
				}, {
					predicate:     newSequence(t, "1-ff00:0:1 0+ 1-ff00:0:3"), // not direct
					minBW:         10,
					maxBW:         42,
					splitCls:      2,
					endProps:      endProps1,
					minActiveRsvs: 1,
				}},
			},
			paths: map[addr.IA][]snet.Path{
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
			},
			reservations: map[addr.IA][]*segment.Reservation{
				xtest.MustParseIA("1-ff00:0:2"): modOneRsv(
					st.NewRsvs(2, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
						st.AddIndex(0, st.WithBW(12, 42, 0),
							st.WithExpiration(tomorrow)),
						st.AddIndex(1, st.WithBW(12, 24, 0),
							st.WithExpiration(tomorrow.Add(24*time.Hour))),
						st.ConfirmAllIndices(),
						st.WithActiveIndex(0),
						st.WithTrafficSplit(2),
						st.WithEndProps(endProps1)),
					0, st.ModIndex(0, st.WithBW(3, 0, 0))), // change rsv 0 to could_be_compliant
				xtest.MustParseIA("1-ff00:0:3"): modOneRsv(
					st.NewRsvs(2, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3"),
						st.AddIndex(0, st.WithBW(12, 42, 0),
							st.WithExpiration(tomorrow)),
						st.AddIndex(1, st.WithBW(12, 24, 0),
							st.WithExpiration(tomorrow.Add(24*time.Hour))),
						st.ConfirmAllIndices(),
						st.WithActiveIndex(0),
						st.WithTrafficSplit(2),
						st.WithEndProps(endProps1)),
					0, st.ModIndex(0, st.WithBW(3, 0, 0))), // change rsv 0 to could_be_compliant
			},
			expectedRequestsCalls: 2,
			expectedWakeupTime:    now.Add(sleepAtMost),
		},
		"all compliant expiring tomorrow": {
			destinations: map[addr.IA][]requirementsDeleteme{
				xtest.MustParseIA("1-ff00:0:2"): {{
					predicate:     newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:         10,
					maxBW:         42,
					splitCls:      2,
					endProps:      endProps1,
					minActiveRsvs: 1,
				}},
			},
			paths: map[addr.IA][]snet.Path{
				xtest.MustParseIA("1-ff00:0:2"): {
					te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"), // direct
				},
			},
			reservations: map[addr.IA][]*segment.Reservation{
				xtest.MustParseIA("1-ff00:0:2"): st.NewRsvs(1,
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
					st.AddIndex(0, st.WithBW(12, 42, 0), st.WithExpiration(tomorrow)),
					st.AddIndex(1, st.WithBW(12, 24, 0),
						st.WithExpiration(tomorrow.Add(24*time.Hour))),
					st.WithActiveIndex(0),
					st.WithTrafficSplit(2),
					st.WithEndProps(endProps1)),
			},
			expectedRequestsCalls: 0,
			expectedWakeupTime:    now.Add(sleepAtMost),
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

			manager := mockManager(ctrl, now, localIA)
			keeper := keeper{
				manager:   manager,
				deletemes: tc.destinations,
			}
			manager.EXPECT().GetReservationsAtSource(gomock.Any(), gomock.Any()).
				Times(len(tc.destinations)).DoAndReturn(
				func(_ context.Context, dstIA addr.IA) (
					[]*segment.Reservation, error) {

					return tc.reservations[dstIA], nil
				})
			manager.EXPECT().PathsTo(gomock.Any(),
				gomock.Any()).Times(len(tc.destinations)).DoAndReturn(
				func(_ context.Context, dstIA addr.IA) ([]snet.Path, error) {
					return tc.paths[dstIA], nil
				})
			manager.EXPECT().SetupManyRequest(gomock.Any(), gomock.Any()).
				Times(tc.expectedRequestsCalls).DoAndReturn(
				func(_ context.Context, reqs []*segment.SetupReq) []error {
					return make([]error, len(reqs))
				})
			manager.EXPECT().ActivateManyRequest(
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).AnyTimes().DoAndReturn(
				func(
					_ context.Context,
					reqs []*base.Request,
					steps []base.PathSteps,
					paths []slayerspath.Path,
				) []error {
					return make([]error, len(reqs), len(paths))
				})

			wakeupTime, err := keeper.OneShotDeleteme(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.expectedWakeupTime, wakeupTime)
		})
	}
}

func TestSetupsPerDestination(t *testing.T) {
	cases := map[string]struct {
		requirements  []requirementsDeleteme
		paths         []snet.Path
		expectedCalls int
	}{
		"regular": {
			requirements: []requirementsDeleteme{
				{
					predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps: reservation.StartLocal | reservation.EndLocal |
						reservation.EndTransfer,
					minActiveRsvs: 1,
				},
				{
					predicate: newSequence(t, "1-ff00:0:1 0+ 1-ff00:0:2"), // not direct
					minBW:     10,
					maxBW:     42,
					splitCls:  2,
					endProps: reservation.StartLocal | reservation.EndLocal |
						reservation.EndTransfer,
					minActiveRsvs: 1,
				},
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"), // direct
				te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"), // direct
				te.NewSnetPath("1-ff00:0:1", 3, 88, "1-ff00:0:88", 99, 4, "1-ff00:0:2"),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			now := util.SecsToTime(10)
			localIA := xtest.MustParseIA("1-ff00:0:1")
			dstIA := xtest.MustParseIA("1-ff00:0:2")
			noRsvs := []*segment.Reservation{}
			manager := mockManager(ctrl, now, localIA)
			keeper := keeper{
				manager: manager,
			}
			manager.EXPECT().SetupManyRequest(
				gomock.Any(),
				gomock.Any(),
			).Times(2).DoAndReturn(
				func(_ context.Context, reqs []*segment.SetupReq) []error {
					return make([]error, len(reqs))
				})
			manager.EXPECT().ActivateManyRequest(
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).AnyTimes()

			_, err := keeper.setupsPerDestination(ctx, dstIA, tc.requirements, tc.paths, noRsvs)
			require.NoError(t, err)
		})
	}
}

func TestRequestNSuccessfulRsvs(t *testing.T) {
	cases := map[string]struct {
		requirements      requirementsDeleteme
		paths             []snet.Path
		requiredCount     int // amount of rsvs we want
		successfulPerCall int // manager will only obtain these per call
		expectError       bool
		expectedReqs      []int // setup request # expected at the manager, per call. nil == error
	}{
		"empty": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, ""),
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths:             []snet.Path{},
			requiredCount:     1,
			successfulPerCall: 1,
			expectError:       true,
		},
		"ask 2 get 2": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 111, "1-ff00:0:666", 222, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 222, "1-ff00:0:666", 333, 2, "1-ff00:0:2"),
			},
			requiredCount:     2,
			successfulPerCall: 2,
			expectedReqs:      []int{2},
		},
		"ask too many": { // predicate(4 paths) -> 2 paths -> 2 requests; but desired is 4
			requirements: requirementsDeleteme{
				predicate: newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"), // direct
				te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"), // direct
				te.NewSnetPath("1-ff00:0:1", 1, 111, "1-ff00:0:666", 222, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 222, "1-ff00:0:666", 333, 2, "1-ff00:0:2"),
			},
			requiredCount:     4,
			successfulPerCall: 4,
			expectError:       true,
			expectedReqs:      []int{2},
		},
		"ask 3 return 2": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, ""),
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 111, "1-ff00:0:666", 222, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 222, "1-ff00:0:666", 333, 2, "1-ff00:0:2"),
			},
			requiredCount:     3,
			successfulPerCall: 2,
			expectedReqs:      []int{3, 1},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			now := util.SecsToTime(10)
			localIA := xtest.MustParseIA("1-ff00:0:1")
			dstIA := xtest.MustParseIA("1-ff00:0:2")

			manager := mockManager(ctrl, now, localIA)
			keeper := keeper{
				manager:   manager,
				deletemes: map[addr.IA][]requirementsDeleteme{dstIA: {tc.requirements}},
			}
			// prepare the sequence of returns from the manager
			managerMutex := new(sync.Mutex)
			requestsCount := make([]int, len(tc.expectedReqs))
			var callCount int
			manager.EXPECT().SetupManyRequest(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(_ context.Context, reqs []*segment.SetupReq) []error {
					managerMutex.Lock()
					defer managerMutex.Unlock()

					if callCount > len(requestsCount) {
						require.FailNow(t, "unexpected call")
					}
					requestsCount[callCount] = len(reqs)
					callCount++
					errs := make([]error, len(reqs))
					for i := 0; i < len(reqs)-tc.successfulPerCall; i++ {
						errs[i] = fmt.Errorf("fake error")
					}
					return errs
				})
			manager.EXPECT().ActivateManyRequest(
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).AnyTimes()
			// build requests from paths (tested elsewhere)
			requests, err := tc.requirements.PrepareSetupRequests(
				tc.paths,
				localIA.AS(),
				now,
				now.Add(time.Hour),
			)
			require.NoError(t, err)
			// call and check
			err = keeper.requestNSuccessfulRsvs(ctx, dstIA,
				tc.requirements, requests, tc.requiredCount)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, len(tc.expectedReqs), callCount)
			if callCount == 0 {
				requestsCount = nil // because Equal would fail otherwise
			}
			require.Equal(t, tc.expectedReqs, requestsCount)
		})
	}
}

func TestRequirementsFilter(t *testing.T) {
	now := util.SecsToTime(0)
	tomorrow := now.Add(3600 * 24 * time.Second)
	reqs := requirementsDeleteme{
		predicate:     newSequence(t, "1-ff00:0:1#0,1 1-ff00:0:2 0*"),
		minBW:         10,
		maxBW:         42,
		splitCls:      2,
		endProps:      reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
		minActiveRsvs: 1,
	}

	cases := map[string]struct {
		requirements           requirementsDeleteme
		atLeastUntil           time.Time
		expectedCompliant      int
		expectedNeedActivation int
		expectedNeedIndices    int
		rsvs                   []*segment.Reservation
	}{
		"empty": {
			requirements: reqs,
			atLeastUntil: now,
			rsvs:         nil,
		},
		"three_identical": {
			requirements:      reqs,
			atLeastUntil:      now,
			expectedCompliant: 3,
			rsvs: st.NewRsvs(3, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 42, 0), st.WithExpiration(tomorrow)),
				st.AddIndex(1, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow.Add(24*time.Hour))),
				st.ConfirmAllIndices(),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
		},
		"a pending (non active) index of all rsvs is uncompliant": {
			requirements:      reqs,
			atLeastUntil:      now,
			expectedCompliant: 3,
			rsvs: st.NewRsvs(3, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 42, 0), st.WithExpiration(tomorrow)),
				// next index is uncompliant
				st.AddIndex(1, st.WithBW(3, 24, 0), st.WithExpiration(tomorrow.Add(24*time.Hour))),
				st.ConfirmAllIndices(),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
		},
		"active index of first rsv is uncompliant but still one compliant index": {
			requirements:      reqs,
			atLeastUntil:      now,
			expectedCompliant: 3,
			rsvs: modOneRsv(st.NewRsvs(3, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 42, 0), st.WithExpiration(tomorrow)),
				st.AddIndex(1, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow.Add(24*time.Hour))),
				st.ConfirmAllIndices(),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
				0, st.ModIndex(0, st.WithBW(3, 0, 0))), // index 0 of rsv 0
		},
		"first rsv with two indices, both uncompliant": {
			requirements:        reqs,
			atLeastUntil:        now,
			expectedCompliant:   2,
			expectedNeedIndices: 1,
			rsvs: modOneRsv(st.NewRsvs(3, st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 42, 0), st.WithExpiration(tomorrow)),
				st.AddIndex(1, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow.Add(24*time.Hour))),
				st.ConfirmAllIndices(),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
				0,                                   // first reservation
				st.ModIndex(0, st.WithBW(3, 0, 0)),  // index 0
				st.ModIndex(1, st.WithBW(3, 0, 0))), // index 1
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			compliant, needsActivation, needsIndices, neverCompliant :=
				tc.requirements.SplitByCompliance(tc.rsvs, tc.atLeastUntil)
			require.Len(t, compliant, tc.expectedCompliant)
			require.Len(t, needsActivation, tc.expectedNeedActivation)
			require.Len(t, needsIndices, tc.expectedNeedIndices)
			require.Len(t, neverCompliant, len(tc.rsvs)-tc.expectedCompliant-
				tc.expectedNeedActivation-tc.expectedNeedIndices)
		})
	}
}

func TestRequirementsCompliance(t *testing.T) {
	now := util.SecsToTime(0)
	tomorrow := now.Add(3600 * 24 * time.Second)
	reqs := requirementsDeleteme{
		pathType:      reservation.UpPath,
		predicate:     newSequence(t, "1-ff00:0:1 1-ff00:0:2"), // direct
		minBW:         10,
		maxBW:         42,
		splitCls:      2,
		endProps:      reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
		minActiveRsvs: 1,
	}
	cases := map[string]struct {
		requirements       requirementsDeleteme
		rsv                *segment.Reservation
		atLeastUntil       time.Time
		expectedCompliance Compliance
	}{
		"compliant, one index": {
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithPathType(reservation.UpPath),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: Compliant,
		},
		"bad path type": {
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithPathType(reservation.DownPath),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeverCompliant,
		},
		"one compliant index but bad traffic split": {
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(1),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeverCompliant,
		},
		"bad end props": {
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reservation.EndLocal)),
			atLeastUntil:       now,
			expectedCompliance: NeverCompliant,
		},
		"bad path": {
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 2, "1-ff00:0:3", 3, 1, "1-ff00:0:2"),
				st.AddIndex(0, st.WithBW(12, 24, 0), st.WithExpiration(tomorrow)),
				st.WithActiveIndex(0),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeverCompliant,
		},
		"one non compliant index, minbw": {
			requirements: reqs,
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
			requirements: reqs,
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
			requirements: reqs,
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
			requirements: reqs,
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
			requirements: reqs,
			rsv: st.NewRsv(st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
				st.WithPathType(reservation.UpPath),
				st.WithTrafficSplit(2),
				st.WithEndProps(reqs.endProps)),
			atLeastUntil:       now,
			expectedCompliance: NeedsIndices,
		},
		"compliant in the past, not now": {
			requirements: reqs,
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
			cmplnce := tc.requirements.Compliance(tc.rsv, tc.atLeastUntil)
			require.Equal(t, tc.expectedCompliance, cmplnce,
				"expected %s got %s", tc.expectedCompliance, cmplnce)
		})
	}
}

func TestEntryPrepareSetupRequests(t *testing.T) {
	cases := map[string]struct {
		requirements requirementsDeleteme
		paths        []snet.Path
		expected     int
	}{
		"empty": {
			requirements: requirementsDeleteme{},
			paths:        nil,
			expected:     0,
		},
		"no paths": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, "1-ff00:0:1 0* 1-ff00:0:2"),
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths:    []snet.Path{},
			expected: 0,
		},
		"starts here and ends there": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, "1-ff00:0:1 0* 1-ff00:0:2"),
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:1", 1, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 2, 3, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 111, "1-ff00:0:666", 222, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:1", 1, 222, "1-ff00:0:666", 333, 2, "1-ff00:0:2"),
			},
			expected: 4,
		},
		"all filtered out": {
			requirements: requirementsDeleteme{
				predicate: newSequence(t, "1-ff00:0:1 0* 1-ff00:0:2"),
				minBW:     10,
				maxBW:     42,
				splitCls:  2,
				endProps: reservation.StartLocal | reservation.EndLocal |
					reservation.EndTransfer,
				minActiveRsvs: 1,
			},
			paths: []snet.Path{
				te.NewSnetPath("1-ff00:0:81", 1, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:81", 2, 3, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:81", 1, 111, "1-ff00:0:666", 222, 2, "1-ff00:0:2"),
				te.NewSnetPath("1-ff00:0:81", 1, 222, "1-ff00:0:666", 333, 2, "1-ff00:0:2"),
			},
			expected: 0,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := util.SecsToTime(10)
			localIA := xtest.MustParseIA("1-ff00:0:1")
			requests, err := tc.requirements.PrepareSetupRequests(tc.paths, localIA.AS(),
				now, now.Add(time.Hour))
			require.NoError(t, err)
			require.Len(t, requests, tc.expected)
			filtered := tc.requirements.predicate.Eval(tc.paths)
			require.Len(t, filtered, tc.expected) // this is internal, but forces 1 req per path
			bagOfPaths := make(map[string]struct{}, len(filtered))
			for _, p := range filtered {
				steps, err := base.StepsFromSnet(p)
				require.NoError(t, err)
				k := steps.String()
				_, ok := bagOfPaths[k]
				require.False(t, ok, "duplicated path in test", p)
				bagOfPaths[k] = struct{}{}
			}
			for _, req := range requests {
				// check req.PathToDst is in filtered paths
				_, ok := bagOfPaths[req.Steps.String()]
				require.True(t, ok, "path: %s, len(bag)=%d, bag:%s", req.Steps,
					len(bagOfPaths), bagOfPaths)
				delete(bagOfPaths, req.Steps.String())
				// check the rest of the request
				require.Equal(t, tc.requirements.minBW, req.MinBW)
				require.Equal(t, tc.requirements.maxBW, req.MaxBW)
				require.Equal(t, tc.requirements.splitCls, req.SplitCls)
				require.Equal(t, tc.requirements.endProps, req.PathProps)
				require.Len(t, req.AllocTrail, 0)
			}
		})
	}
}

func TestEntrySelectRequests(t *testing.T) {
	entry := requirementsDeleteme{
		predicate:     newSequence(t, "1-ff00:0:1#0,1 1-ff00:0:2 0*"),
		minBW:         10,
		maxBW:         42,
		splitCls:      2,
		endProps:      reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
		minActiveRsvs: 1,
	}
	cases := map[string]struct {
		requests    []*segment.SetupReq
		n           int
		expectedLen int
	}{
		"regular": {
			requests:    make([]*segment.SetupReq, 8),
			n:           3,
			expectedLen: 3,
		},
		"no requests": {
			requests:    make([]*segment.SetupReq, 0),
			n:           3,
			expectedLen: 0,
		},
		"asked too many": {
			requests:    make([]*segment.SetupReq, 8),
			n:           9,
			expectedLen: 8,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			indices := entry.SelectRequests(tc.requests, tc.n)
			require.Len(t, indices, tc.expectedLen)
			visited := make(map[int]struct{}, len(indices))
			for _, idx := range indices {
				_, ok := visited[idx]
				require.False(t, ok, "selected indices have duplicates: %v", indices)
				visited[idx] = struct{}{}
				require.Less(t, idx, len(tc.requests))
			}
		})
	}
}

func TestSplitRequests(t *testing.T) {
	cases := map[string]struct {
		reqs []*segment.SetupReq
		idxs []int
		a    []*segment.SetupReq
		b    []*segment.SetupReq
	}{
		"empty": {
			reqs: fakeReqs(),
			idxs: []int{},
			a:    fakeReqs(),
			b:    fakeReqs(),
		},
		"no_indices": {
			reqs: fakeReqs(0),
			idxs: []int{},
			a:    fakeReqs(),
			b:    fakeReqs(0),
		},
		"all_a": {
			reqs: fakeReqs(0, 1, 2),
			idxs: []int{1, 2, 0},
			a:    fakeReqs(1, 2, 0),
			b:    fakeReqs(),
		},
		"sides": {
			reqs: fakeReqs(0, 1, 2, 3),
			idxs: []int{3, 0},
			a:    fakeReqs(3, 0),
			b:    fakeReqs(1, 2),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := splitRequests(tc.reqs, tc.idxs)
			require.Equal(t, tc.a, a)
			require.ElementsMatch(t, tc.b, b)
		})
	}
}

func TestParseInitial(t *testing.T) {
	cases := map[string]struct {
		conf            conf.Reservations
		expectedEntries map[addr.IA][]requirementsDeleteme
		expectedError   bool
	}{
		"empty": {
			conf:            conf.Reservations{},
			expectedEntries: map[addr.IA][]requirementsDeleteme{},
		},
		"good": {
			conf: conf.Reservations{Rsvs: []conf.ReservationEntry{
				{
					DstAS:         xtest.MustParseIA("1-ff00:0:2"),
					PathType:      reservation.UpPath,
					PathPredicate: "",
					MinSize:       1,
					MaxSize:       2,
					SplitCls:      3,
					EndProps:      conf.EndProps(reservation.EndLocal),
					RequiredCount: 2,
				},
			}},
			expectedEntries: map[addr.IA][]requirementsDeleteme{
				xtest.MustParseIA("1-ff00:0:2"): {
					{
						pathType:      reservation.UpPath,
						predicate:     newSequence(t, ""),
						minBW:         1,
						maxBW:         2,
						splitCls:      3,
						endProps:      reservation.EndLocal,
						minActiveRsvs: 2,
					},
				},
			},
		},
		"bad predicate": {
			conf: conf.Reservations{Rsvs: []conf.ReservationEntry{
				{
					DstAS:         xtest.MustParseIA("1-ff00:0:2"),
					PathPredicate: ")",
					MinSize:       1,
					MaxSize:       2,
					SplitCls:      3,
					EndProps:      conf.EndProps(reservation.EndLocal),
					RequiredCount: 2,
				},
			}},
			expectedError: true,
		},
		"bad min bw": {
			conf: conf.Reservations{Rsvs: []conf.ReservationEntry{
				{
					DstAS:         xtest.MustParseIA("1-ff00:0:2"),
					PathPredicate: "",
					MinSize:       11,
					MaxSize:       2,
					SplitCls:      3,
					EndProps:      conf.EndProps(reservation.EndLocal),
					RequiredCount: 2,
				},
			}},
			expectedError: true,
		},
		"bad max bw": {
			conf: conf.Reservations{Rsvs: []conf.ReservationEntry{
				{
					DstAS:         xtest.MustParseIA("1-ff00:0:2"),
					PathPredicate: "",
					MinSize:       1,
					MaxSize:       0,
					SplitCls:      3,
					EndProps:      conf.EndProps(reservation.EndLocal),
					RequiredCount: 2,
				},
			}},
			expectedError: true,
		},
		"bad required count": {
			conf: conf.Reservations{Rsvs: []conf.ReservationEntry{
				{
					DstAS:         xtest.MustParseIA("1-ff00:0:2"),
					PathPredicate: "",
					MinSize:       1,
					MaxSize:       2,
					SplitCls:      3,
					EndProps:      conf.EndProps(reservation.EndLocal),
					RequiredCount: 0,
				},
			}},
			expectedError: true,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entries, err := parseInitialDeleteme(&tc.conf)
			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedEntries, entries)
		})
	}
}

func fakeReqs(ids ...int) []*segment.SetupReq {
	reqs := make([]*segment.SetupReq, len(ids))
	for i, id := range ids {
		reqs[i] = fakeReq(id)
	}
	return reqs
}

func fakeReq(id int) *segment.SetupReq {
	return &segment.SetupReq{
		MinBW: reservation.BWCls(id),
	}
}

func newSequence(t *testing.T, str string) *pathpol.Sequence {
	t.Helper()
	seq, err := pathpol.NewSequence(str)
	xtest.FailOnErr(t, err)
	return seq
}

func modOneRsv(rsvs []*segment.Reservation, whichRsv int,
	mods ...st.ReservationMod) []*segment.Reservation {

	rsvs[whichRsv] = st.ModRsv(rsvs[whichRsv], mods...)
	return rsvs
}

func mockManager(ctrl *gomock.Controller, now time.Time,
	localIA addr.IA) *mockmanager.MockManager {

	m := mockmanager.NewMockManager(ctrl)
	m.EXPECT().LocalIA().AnyTimes().Return(localIA)
	m.EXPECT().Now().AnyTimes().Return(now)
	return m
}
