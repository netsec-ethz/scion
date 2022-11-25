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

package segment_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/segmenttest"
	"github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/util"
)

func TestNewIndex(t *testing.T) {
	r := segmenttest.NewReservation()
	require.Len(t, r.Indices, 0)
	expTime := util.SecsToTime(1)
	idx, err := r.NewIndex(0, expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, reservation.IndexNumber(0), idx)
	require.Equal(t, idx, r.Indices[0].Idx)
	require.Equal(t, expTime, r.Indices[0].Expiration)
	require.Equal(t, segment.IndexTemporary, r.Indices[0].State)
	require.Equal(t, reservation.BWCls(1), r.Indices[0].MinBW)
	require.Equal(t, reservation.BWCls(3), r.Indices[0].MaxBW)
	require.Equal(t, reservation.BWCls(2), r.Indices[0].AllocBW)
	require.NotNil(t, r.Indices[0].Token)
	tok := &reservation.Token{
		InfoField: reservation.InfoField{
			ExpirationTick: reservation.TickFromTime(expTime),
			BWCls:          2,
			RLC:            5,
			Idx:            idx,
			PathType:       reservation.CorePath,
		},
	}
	require.Equal(t, tok, r.Indices[0].Token)
	// add a second index
	idx, err = r.NewIndex(1, expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 2)
	require.Equal(t, reservation.IndexNumber(1), idx)
	require.Equal(t, idx, r.Indices[1].Idx)
	// remove first index and add another one
	r.Indices = r.Indices[1:]
	idx, err = r.NewIndex(2, expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 2)
	require.Equal(t, reservation.IndexNumber(2), idx)
	require.Equal(t, idx, r.Indices[1].Idx)
}

func TestReservationValidate(t *testing.T) {
	r := segmenttest.NewReservation()
	err := r.Validate()
	require.NoError(t, err)
	// wrong path
	r.Steps = nil
	err = r.Validate()
	require.Error(t, err)
	// more than one active index
	expTime := util.SecsToTime(1)
	r = segmenttest.NewReservation()
	r.NewIndex(0, expTime, 0, 0, 0, 0, reservation.CorePath)
	r.NewIndex(1, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 2)
	r.Indices[0].SetStateForTesting(segment.IndexActive)
	r.Indices[1].SetStateForTesting(segment.IndexActive)
	err = r.Validate()
	require.Error(t, err)
	// ID not set
	r = segmenttest.NewReservation()
	r.ID = reservation.ID{}
	err = r.Validate()
	require.Error(t, err)
	// starts in this AS but ingress nonzero
	r = segmenttest.NewReservation()
	r.Steps[r.CurrentStep].Ingress = 1
	err = r.Validate()
	require.Error(t, err)
	// Does not start in this AS but ingress empty
	r = segmenttest.NewReservation()
	r.Steps = nil
	err = r.Validate()
	require.Error(t, err)
}

func TestIndex(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	r.NewIndex(0, expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ := r.NewIndex(1, expTime, 0, 0, 0, 0, reservation.CorePath)
	r.NewIndex(2, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 3)
	index := r.Index(idx)
	require.Equal(t, &r.Indices[1], index)
	index = r.Index(reservation.IndexNumber(4))
	require.Nil(t, index)
	r.SetIndexConfirmed(idx)
	r.SetIndexActive(idx)
	index = r.Index(idx)
	require.Equal(t, &r.Indices[0], index)
}

func TestSetIndexConfirmed(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	id, _ := r.NewIndex(0, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Equal(t, segment.IndexTemporary, r.Indices[0].State)
	err := r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, segment.IndexPending, r.Indices[0].State)

	// confirm already confirmed
	err = r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, segment.IndexPending, r.Indices[0].State)
}

func TestSetIndexActive(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)

	// index not confirmed
	idx, _ := r.NewIndex(0, expTime, 0, 0, 0, 0, reservation.CorePath)
	err := r.SetIndexActive(idx)
	require.Error(t, err)

	// normal activation
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Equal(t, segment.IndexActive, r.Indices[0].State)
	require.Equal(t, 0, r.GetActiveIndexForTesting())

	// already active
	err = r.SetIndexActive(idx)
	require.NoError(t, err)

	// remove previous indices
	r.NewIndex(1, expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ = r.NewIndex(2, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 3)
	require.Equal(t, 0, r.GetActiveIndexForTesting())
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, 0, r.GetActiveIndexForTesting())
	require.True(t, r.Indices[0].Idx == idx)
}

func TestRemoveIndex(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	idx, _ := r.NewIndex(0, expTime, 0, 0, 0, 0, reservation.CorePath)
	err := r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)

	// remove second index
	idx, _ = r.NewIndex(1, expTime, 0, 0, 0, 0, reservation.CorePath)
	idx2, _ := r.NewIndex(2, expTime, 0, 0, 0, 0, reservation.CorePath)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.True(t, r.Indices[0].Idx == idx2)
	err = r.Validate()
	require.NoError(t, err)

	// remove also removes older indices
	expTime = expTime.Add(time.Second)
	r.NewIndex(3, expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ = r.NewIndex(4, expTime, 0, 0, 0, 0, reservation.CorePath)
	idx2, _ = r.NewIndex(5, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 4)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.True(t, r.Indices[0].Idx == idx2)
	err = r.Validate()
	require.NoError(t, err)
}

func TestMaxBlockedBW(t *testing.T) {
	r := segmenttest.NewReservation()
	r.Indices = r.Indices[:0]
	require.Equal(t, uint64(0), r.MaxBlockedBW())
	r.NewIndex(0, util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.Equal(t, reservation.BWCls(1).ToKbps(), r.MaxBlockedBW())
	r.NewIndex(1, util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.Equal(t, reservation.BWCls(1).ToKbps(), r.MaxBlockedBW())
	r.Indices[0].AllocBW = 11
	require.Equal(t, reservation.BWCls(11).ToKbps(), r.MaxBlockedBW())
}

func TestDeriveColibriPathAtSource(t *testing.T) {

	cases := map[string]struct {
		SegR *segment.Reservation
	}{
		"up": {
			SegR: &segment.Reservation{
				PathType:    reservation.UpPath,
				Steps:       test.NewSteps("1-ff00:0:1", 1, 2, "1-ff00:0:2", 3, 4, "1-ff00:0:3"),
				CurrentStep: 1,
				ID:          *test.MustParseID("ff00:0:1", "01234567"),
				Indices: segment.Indices{segment.Index{
					Token: &reservation.Token{
						InfoField: reservation.InfoField{
							Idx:            1,
							BWCls:          3,
							ExpirationTick: reservation.TickFromTime(util.SecsToTime(1000)),
						},
						HopFields: []reservation.HopField{
							{
								Ingress: 0,
								Egress:  1,
							},
							{
								Ingress: 2,
								Egress:  3,
							},
							{
								Ingress: 4,
								Egress:  0,
							},
						},
					},
				}},
			},
		},
		"down": {
			SegR: &segment.Reservation{
				PathType:    reservation.DownPath,
				Steps:       test.NewSteps("1-ff00:0:3", 4, 3, "1-ff00:0:2", 2, 1, "1-ff00:0:1"),
				CurrentStep: 1,
				ID:          *test.MustParseID("ff00:0:1", "01234567"),
				Indices: segment.Indices{segment.Index{
					Token: &reservation.Token{
						InfoField: reservation.InfoField{
							Idx:            1,
							BWCls:          3,
							ExpirationTick: reservation.TickFromTime(util.SecsToTime(1000)),
						},
						HopFields: []reservation.HopField{
							{
								Ingress: 0,
								Egress:  4,
							},
							{
								Ingress: 3,
								Egress:  2,
							},
							{
								Ingress: 1,
								Egress:  0,
							},
						},
					},
				}},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			colibriKeys := test.InitColibriKeys(t, len(tc.SegR.Steps))
			srcAS := tc.SegR.Steps.SrcIA().AS()
			dstAS := tc.SegR.Steps.DstIA().AS()
			test.TraverseASesAndStampMACs(t, tc.SegR, colibriKeys, srcAS, dstAS)
			colPath := colibriMinimalToRegular(t, tc.SegR.DeriveColibriPathAtSource())
			test.VerifyMACs(t, colPath, colibriKeys, srcAS, dstAS)
		})
	}
}

func TestDeriveColibriPathAtDestination(t *testing.T) {

	cases := map[string]struct {
		SegR *segment.Reservation
	}{
		"down": {
			SegR: &segment.Reservation{
				PathType: reservation.DownPath,
				// steps always in the direction of the traffic
				Steps:       test.NewSteps("1-ff00:0:3", 4, 3, "1-ff00:0:2", 2, 1, "1-ff00:0:1"),
				CurrentStep: 1,
				ID:          *test.MustParseID("ff00:0:1", "01234567"),
				Indices: segment.Indices{segment.Index{
					Token: &reservation.Token{
						InfoField: reservation.InfoField{
							Idx:            1,
							BWCls:          3,
							ExpirationTick: reservation.TickFromTime(util.SecsToTime(1000)),
						},
						HopFields: []reservation.HopField{
							{
								Ingress: 0,
								Egress:  4,
							},
							{
								Ingress: 3,
								Egress:  2,
							},
							{
								Ingress: 1,
								Egress:  0,
							},
						},
					},
				}},
			},
		},
		"longlegs": {
			SegR: &segment.Reservation{
				PathType: reservation.DownPath, // initiated by 113
				// steps always in the direction of the traffic
				Steps: test.NewSteps("1-ff00:0:110", 1, 41, "1-ff00:0:111", 2, 1, "1-ff00:0:113"),
				//
				CurrentStep: 1,
				ID:          *test.MustParseID("ff00:0:113", "01234567"),
				Indices: segment.Indices{segment.Index{
					Token: &reservation.Token{
						InfoField: reservation.InfoField{
							Idx:            1,
							BWCls:          3,
							ExpirationTick: reservation.TickFromTime(util.SecsToTime(1000)),
						},
						HopFields: []reservation.HopField{
							{ // 110
								Ingress: 0,
								Egress:  1,
							},
							{ // 111
								Ingress: 41,
								Egress:  2,
							},
							{ // 113
								Ingress: 1,
								Egress:  0,
							},
						},
					},
				}},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			colibriKeys := test.InitColibriKeys(t, len(tc.SegR.Steps))
			srcAS := tc.SegR.Steps.SrcIA().AS() // e.g. 110 in the "longlegs"
			dstAS := tc.SegR.Steps.DstIA().AS() // e.g. 113 in the "longlegs"
			test.TraverseASesAndStampMACs(t, tc.SegR, colibriKeys, srcAS, dstAS)
			colPath := colibriMinimalToRegular(t, tc.SegR.DeriveColibriPathAtDestination())
			// Because the SCION layer reverses the src and dst ASes, simulate it here:
			srcAS, dstAS = dstAS, srcAS
			// also reverse the order of the keys per AS, so that they are picked up correctly
			for i := 0; i < len(colibriKeys)/2; i++ {
				colibriKeys[i], colibriKeys[len(colibriKeys)-i-1] =
					colibriKeys[len(colibriKeys)-i-1], colibriKeys[i]
			}
			test.VerifyMACs(t, colPath, colibriKeys, srcAS, dstAS)
		})
	}
}

func colibriMinimalToRegular(t *testing.T, min *colpath.ColibriPathMinimal) *colpath.ColibriPath {
	require.NotNil(t, min)
	colPath, err := min.ToColibriPath()
	require.NoError(t, err)
	return colPath
}
