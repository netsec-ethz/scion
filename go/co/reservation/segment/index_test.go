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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
)

func TestIndexFilters(t *testing.T) {
	now := util.SecsToTime(10)
	cases := map[string]struct {
		index    Index
		filter   IndexFilter
		expected bool
	}{
		"expires exactly then": {
			index:    Index{Expiration: now},
			filter:   ByExpiration(now),
			expected: false,
		},
		"expires before than the argument": {
			index:    Index{Expiration: now.Add(-time.Nanosecond)},
			filter:   ByExpiration(now),
			expected: false,
		},
		"expires after": {
			index:    Index{Expiration: now.Add(time.Nanosecond)},
			filter:   ByExpiration(now),
			expected: true,
		},
		"same minBW": {
			index:    Index{MinBW: 2},
			filter:   ByMinBW(2),
			expected: true,
		},
		"lower minBW": {
			index:    Index{MinBW: 1},
			filter:   ByMinBW(2),
			expected: false,
		},
		"higher minBW": {
			index:    Index{MinBW: 3},
			filter:   ByMinBW(2),
			expected: true,
		},
		"same maxBW": {
			index:    Index{MaxBW: 2},
			filter:   ByMaxBW(2),
			expected: true,
		},
		"lower maxBW": {
			index:    Index{MaxBW: 1},
			filter:   ByMaxBW(2),
			expected: true,
		},
		"higher maxBW": {
			index:    Index{MaxBW: 3},
			filter:   ByMaxBW(2),
			expected: false,
		},
		"confirmed (pending)": {
			index:    Index{State: IndexPending},
			filter:   NotConfirmed(),
			expected: true,
		},
		"confirmed (active)": {
			index:    Index{State: IndexActive},
			filter:   NotConfirmed(),
			expected: true,
		},
		"not confirmed (temporary)": {
			index:    Index{State: IndexTemporary},
			filter:   NotConfirmed(),
			expected: false,
		},
		"same index": {
			index: Index{
				Expiration: now,
				State:      IndexActive},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexActive}),
			expected: true,
		},
		"future index": {
			index: Index{
				Expiration: now.Add(time.Second),
				State:      IndexPending},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexActive}),
			expected: true,
		},
		"future index from pending": {
			index: Index{
				Expiration: now.Add(time.Second),
				State:      IndexPending},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexPending}),
			expected: true,
		},
		"future index from temporary": {
			index: Index{
				Expiration: now.Add(time.Second),
				State:      IndexPending},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexTemporary}),
			expected: true,
		},
		"no reference index": {
			index: Index{
				Expiration: now,
				State:      IndexActive},
			filter:   NotSwitchableFrom(nil),
			expected: false,
		},
		"index in the past": {
			index: Index{
				Expiration: now.Add(-time.Second),
				State:      IndexActive},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexPending}),
			expected: false,
		},
		"future index but not confirmed": {
			index: Index{
				Expiration: now.Add(time.Second),
				State:      IndexTemporary},
			filter: NotSwitchableFrom(&Index{
				Expiration: now,
				State:      IndexActive}),
			expected: false,
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, tc.filter(tc.index))
		})
	}
}

func TestFilter(t *testing.T) {
	// `tracer` will be used by the test to track down the sequence of calls to the filters
	type MOCKS func(tracer chan int) IndexFilter
	cases := map[string]struct {
		indices         Indices
		filters         []MOCKS
		expectedCalls   []int
		expectedIndices Indices
	}{
		"no filters": {
			indices:         IND(1, 2, 3),
			filters:         nil,
			expectedIndices: IND(1, 2, 3),
			expectedCalls:   nil,
		},
		"pass all": {
			indices: IND(1, 2),
			filters: []MOCKS{
				func(tracer chan int) IndexFilter {
					return func(_ Index) bool { return true }
				},
			},
			expectedIndices: IND(1, 2),
			expectedCalls:   nil,
		},
		"filter all out": {
			indices: IND(1, 2),
			filters: []MOCKS{
				func(tracer chan int) IndexFilter {
					return func(_ Index) bool { return false }
				},
			},
			expectedIndices: IND(),
			expectedCalls:   nil,
		},
		"no shortcuts": {
			indices: IND(1, 2),
			filters: []MOCKS{
				func(tracer chan int) IndexFilter {
					return func(_ Index) bool {
						tracer <- 1
						return true
					}
				},
			},
			expectedIndices: IND(1, 2),
			expectedCalls:   []int{1, 1},
		},
		"shortcut": {
			indices: IND(1, 2),
			filters: []MOCKS{
				func(tracer chan int) IndexFilter {
					return func(idx Index) bool {
						tracer <- 1111
						tracer <- int(idx.Idx)
						return true
					}
				},
				func(tracer chan int) IndexFilter {
					return func(idx Index) bool {
						tracer <- 2222
						tracer <- int(idx.Idx)
						idx.Idx = 0
						return true
					}
				},
				func(tracer chan int) IndexFilter {
					return func(idx Index) bool {
						tracer <- 3333
						tracer <- int(idx.Idx)
						return idx.Idx <= 1
					}
				},
				func(tracer chan int) IndexFilter {
					return func(idx Index) bool {
						tracer <- 4444
						tracer <- int(idx.Idx)
						return true
					}
				},
			},
			expectedIndices: IND(1),
			expectedCalls:   []int{1111, 1, 2222, 1, 3333, 1, 4444, 1, 1111, 2, 2222, 2, 3333, 2},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tracer := make(chan int) // to trace the calls
			filters := make([]IndexFilter, len(tc.filters))
			for i, fcn := range tc.filters {
				filters[i] = fcn(tracer)
			}
			// run the filters in a different go routine (they may write to a channel)
			var filtered Indices
			go func() {
				filtered = tc.indices.Filter(filters...)
				close(tracer)
			}()
			calls := make([]int, 0)
			for elem := range tracer { // this blocks until the previous go routine closes tracer
				calls = append(calls, elem)
			}

			// check results
			require.Equal(t, tc.expectedIndices, filtered)
			if tc.expectedCalls == nil {
				// because require.Equal(nil, []int{}) == false, patch it here
				tc.expectedCalls = []int{}
			}
			require.Equal(t, tc.expectedCalls, calls)
		})
	}
}

func IND(idxs ...reservation.IndexNumber) Indices {
	indices := make(Indices, len(idxs))
	for i, idx := range idxs {
		indices[i] = Index{
			Idx: idx,
		}
	}
	return indices
}
