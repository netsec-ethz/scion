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

package reservationdbtest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	st "github.com/scionproto/scion/go/co/reservation/segmenttest"
	"github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDB(t *testing.T, newDB func() backend.DB) {
	tests := map[string]func(context.Context, *testing.T, func() backend.DB){
		"insert segment reservations create ID":  testNewSegmentRsv,
		"persist segment reservation":            testPersistSegmentRsv,
		"get segment reservation from ID":        testGetSegmentRsvFromID,
		"get segment reservations from src_dst":  testGetSegmentRsvsFromSrcDstIA,
		"get all segment reservations":           testGetAllSegmentRsvs,
		"get segment reservation from IF pair":   testGetSegmentRsvsFromIFPair,
		"delete segment reservation":             testDeleteSegmentRsv,
		"delete expired indices":                 testDeleteExpiredIndices,
		"test next expiration time":              testNextExpirationTime,
		"persist e2e reservation":                testPersistE2ERsv,
		"get all e2e reservations":               testGetAllE2ERsvs,
		"get e2e reservation from ID":            testGetE2ERsvFromID,
		"get e2e reservations from segment ones": testGetE2ERsvsOnSegRsv,
		"add entries to admission list":          testAddToAdmissionList,
		"check admission list":                   testCheckAdmissionList,
		"state interface blocked":                testGetInterfaceUsage,
		"stateful tables":                        testStatefulTables,
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			test(ctx, t, newDB)
		})
	}
}

func testNewSegmentRsv(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	var err error
	db := newDB()
	r := newTestReservation(t)
	err = r.RemoveIndex(0)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)
	// no indices
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix)
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// at least one index, and change path
	_, err = r.NewIndex(0, util.SecsToTime(10), 2, 3, 2, 2, reservation.CorePath)
	require.NoError(t, err)
	p := test.NewSnetPath("1-ff00:0:1", 2, 1, "1-ff00:0:2")
	r.Steps, err = base.StepsFromSnet(p)
	require.NoError(t, err)
	r.RawPath, err = base.PathFromDataplanePath(p.Dataplane())
	require.NoError(t, err)
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000002"), r.ID.Suffix)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// different ASID should start with the lowest suffix
	r = newTestReservation(t)
	r.ID.ASID = xtest.MustParseAS("ff00:1234:1")
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
}

func testPersistSegmentRsv(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	r := newTestReservation(t)
	for i := uint32(1); i < 10; i++ {
		_, err := r.NewIndex(reservation.IndexNumber(i), util.SecsToTime(i), 0, 0, 0, 0,
			reservation.CorePath)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 10)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// now remove one index
	err = r.RemoveIndex(0)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	require.Len(t, rsv.Indices, 9)
	// change ID
	r.ID.ASID = xtest.MustParseAS("ff00:1:12")
	copy(r.ID.Suffix, xtest.MustParseHexString("beefcafe"))
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// change attributes
	r.Ingress = 3
	r.Egress = 4
	p := test.NewSnetPath("1-ff00:0:1", 11, 1, "1-ff00:0:2")
	r.Steps, err = base.StepsFromSnet(p)
	require.NoError(t, err)
	r.RawPath, err = base.PathFromDataplanePath(p.Dataplane())
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// remove 7 more indices, remains 1 index
	err = r.RemoveIndex(8)
	require.NoError(t, err)
	r.Indices[0].Expiration = util.SecsToTime(12345)
	r.Indices[0].MinBW = 10
	r.Indices[0].MaxBW = 11
	r.Indices[0].AllocBW = 12
	r.Indices[0].Token = newToken() // change the token
	r.Indices[0].Token.BWCls = 8
	err = r.SetIndexConfirmed(r.Indices[0].Idx)
	require.NoError(t, err)
	err = r.SetIndexActive(r.Indices[0].Idx)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	require.Len(t, rsv.Indices, 1)
	// remove the last index
	err = r.RemoveIndex(9)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	require.Len(t, rsv.Indices, 0)
}

func testGetSegmentRsvFromID(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	// create new index
	expTime := util.SecsToTime(1)
	_, err = r.NewIndex(1, expTime, 0, 0, 0, 0, reservation.CorePath)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	// 14 more indices for a total of 16
	require.Len(t, r.Indices, 2)
	for i := 2; i < 16; i++ {
		expTime = util.SecsToTime(uint32(i))
		_, err = r.NewIndex(reservation.IndexNumber(i), expTime, reservation.BWCls(i),
			reservation.BWCls(i), reservation.BWCls(i), 0, reservation.CorePath)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 16)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	r2, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	// wrong ID
	ID := r.ID
	ID.ASID++
	r2, err = db.GetSegmentRsvFromID(ctx, &ID)
	require.NoError(t, err)
	require.Nil(t, r2)
}

func testGetSegmentRsvsFromSrcDstIA(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	cases := map[string]struct {
		srcIA    addr.IA
		dstIA    addr.IA
		pathType reservation.PathType
		rsvs     []*segment.Reservation
		expected []*reservation.ID
	}{
		"empty db": {
			srcIA:    xtest.MustParseIA("1-ff00:0:1"),
			dstIA:    xtest.MustParseIA("1-ff00:0:2"),
			expected: nil,
		},
		"regular": {
			srcIA: xtest.MustParseIA("1-ff00:0:1"),
			dstIA: xtest.MustParseIA("1-ff00:0:2"),
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:3", 1, 1, "1-ff00:0:2")),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000001"),
			},
		},
		"not found": {
			srcIA: xtest.MustParseIA("1-ff00:0:1"),
			dstIA: xtest.MustParseIA("1-ff00:0:20"),
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:3", 1, 1, "1-ff00:0:2")),
			},
			expected: []*reservation.ID{},
		},
		"dst_as wildcard": {
			srcIA: xtest.MustParseIA("1-ff00:0:1"),
			dstIA: xtest.MustParseIA("1-0"), // wildcard
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:1", 1, 1, "11-ff00:0:2")),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000001"),
				test.MustParseID("ff00:0:1", "00000002"),
			},
		},
		"dst_isd wildcard": {
			srcIA: xtest.MustParseIA("1-ff00:0:1"),
			// dstIA: xtest.MustParseIA("0-ff00:0:2"), // wildcard
			dstIA: xtest.MustParseIA("0-ffff:ffff:ffff"), // wildcard
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ffff:ffff:ffff")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:1", 1, 1, "11-ffff:ffff:ffff")),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000001"),
				test.MustParseID("ff00:0:1", "00000003"),
			},
		},
		"src_as wildcard": {
			srcIA: xtest.MustParseIA("11-0"),
			dstIA: xtest.MustParseIA("1-ff00:0:2"), // wildcard
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("11-ff00:0:1", 1, 1, "1-ff00:0:2")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("11-ff00:0:1", 1, 1, "11-ff00:0:2")),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000002"),
			},
		},
		"many wildcards": {
			srcIA: xtest.MustParseIA("0-0"),
			dstIA: xtest.MustParseIA("11-0"), // wildcard
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "11-ff00:0:1")),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3")),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:1", 1, 1, "11-ff00:0:2")),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000001"),
				test.MustParseID("ff00:0:1", "00000003"),
			},
		},
		"up reservation to any core": {
			srcIA:    xtest.MustParseIA("1-ff00:0:1"),
			dstIA:    xtest.MustParseIA("1-0"), // wildcard
			pathType: reservation.UpPath,
			rsvs: []*segment.Reservation{
				st.NewRsv(st.WithID("ff00:0:1", "00000001"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"),
					st.WithPathType(reservation.DownPath)),
				st.NewRsv(st.WithID("ff00:0:1", "00000002"),
					st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:3"), // to a core AS
					st.WithPathType(reservation.UpPath)),
				st.NewRsv(st.WithID("ff00:0:1", "00000003"),
					st.WithPath("1-ff00:0:1", 1, 1, "11-ff00:0:2"), // to a core AS
					st.WithPathType(reservation.UpPath)),
			},
			expected: []*reservation.ID{
				test.MustParseID("ff00:0:1", "00000002"),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db := newDB()
			for _, r := range tc.rsvs {
				err := db.PersistSegmentRsv(ctx, r)
				require.NoError(t, err)
			}
			// sanity check (all rsvs stored in DB)
			rsvs, err := db.GetAllSegmentRsvs(ctx)
			require.NoError(t, err)
			require.Len(t, rsvs, len(tc.rsvs))
			// check the actual function
			rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, tc.srcIA, tc.dstIA, tc.pathType)
			require.NoError(t, err)
			actualIDs := make([]*reservation.ID, len(rsvs))
			for i, r := range rsvs {
				actualIDs[i] = &r.ID
			}
			require.ElementsMatch(t, tc.expected, actualIDs)
		})
	}
}

func testGetAllSegmentRsvs(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	// empty
	rsvs, err := db.GetAllSegmentRsvs(ctx)
	require.NoError(t, err)
	require.Empty(t, rsvs)
	// insert in1,eg1 ; in2,eg1 ; in1,eg2
	r1 := newTestReservation(t)
	r1.Ingress = 11
	r1.Egress = 12
	err = db.NewSegmentRsv(ctx, r1)
	require.NoError(t, err)
	r2 := newTestReservation(t)
	r2.Ingress = 21
	r2.Egress = 12
	err = db.NewSegmentRsv(ctx, r2)
	require.NoError(t, err)
	r3 := newTestReservation(t)
	r3.Ingress = 11
	r3.Egress = 22
	err = db.NewSegmentRsv(ctx, r3)
	require.NoError(t, err)
	// retrieve them
	rsvs, err = db.GetAllSegmentRsvs(ctx)
	require.NoError(t, err)
	expected := []*segment.Reservation{r1, r2, r3}
	require.ElementsMatch(t, expected, rsvs)
}

func testGetSegmentRsvsFromIFPair(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	// insert in1,e1 ; in2,e1 ; in1,e2
	r1 := newTestReservation(t)
	r1.Ingress = 11
	r1.Egress = 12
	err := db.NewSegmentRsv(ctx, r1)
	require.NoError(t, err)
	r2 := newTestReservation(t)
	r2.Ingress = 21
	r2.Egress = 12
	err = db.NewSegmentRsv(ctx, r2)
	require.NoError(t, err)
	r3 := newTestReservation(t)
	r3.Ingress = 11
	r3.Egress = 22
	err = db.NewSegmentRsv(ctx, r3)
	require.NoError(t, err)
	// query with a specific pair
	rsvs, err := db.GetSegmentRsvsFromIFPair(ctx, &r1.Ingress, &r1.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 1)
	expected := []*segment.Reservation{r1}
	require.ElementsMatch(t, expected, rsvs)
	// any ingress
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, nil, &r1.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	expected = []*segment.Reservation{r1, r2}
	require.ElementsMatch(t, expected, rsvs)
	// any egress
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r1.Ingress, nil)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	expected = []*segment.Reservation{r1, r3}
	require.ElementsMatch(t, expected, rsvs)
	// no matches
	var inexistentIngress uint16 = 222
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &inexistentIngress, nil)
	require.NoError(t, err)
	require.Len(t, rsvs, 0)
	// bad query
	_, err = db.GetSegmentRsvsFromIFPair(ctx, nil, nil)
	require.Error(t, err)
}

func testDeleteSegmentRsv(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	err = db.DeleteSegmentRsv(ctx, &r.ID)
	require.NoError(t, err)
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Nil(t, rsv)
	// with no indices
	r = newTestReservation(t)
	err = r.RemoveIndex(0)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	err = db.DeleteSegmentRsv(ctx, &r.ID)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Nil(t, rsv)
}

func testDeleteExpiredIndices(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	// create seg. and e2e reservations that have indices expiring at different times.
	// rX stands for segment rsv. and eX for an e2e. Twice the same symbol means another index.
	// timeline: e1...r1...r2,r3...e2,e3...e3,e4...r3,r4...e5
	//            1    2       3       4       5       6    1000
	// Each eX is linked to a rX, being X the same for both. But e5 is linked to r4.

	// r1, e1
	segIds := make([]reservation.ID, 0)
	r := newTestReservation(t)
	r.Indices[0].Expiration = util.SecsToTime(2)
	err := db.NewSegmentRsv(ctx, r) // save r1
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e := newTestE2EReservation(t)
	e.ID.ASID = xtest.MustParseAS("ff00:0:1")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(1)
	err = db.PersistE2ERsv(ctx, e) // save e1
	require.NoError(t, err)
	// r2, e2
	r.Indices[0].Expiration = util.SecsToTime(3)
	err = db.NewSegmentRsv(ctx, r) // save r2
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.ID.ASID = xtest.MustParseAS("ff00:0:2")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(4)
	err = db.PersistE2ERsv(ctx, e) // save e2
	require.NoError(t, err)
	// r3, e3
	r.Indices[0].Expiration = util.SecsToTime(3)
	r.NewIndex(1, util.SecsToTime(6), 1, 3, 2, 5, reservation.CorePath)
	err = db.NewSegmentRsv(ctx, r) // save r3
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.ID.ASID = xtest.MustParseAS("ff00:0:3")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(4)
	e.Indices[0].Token.ExpirationTick = reservation.TickFromTime(e.Indices[0].Expiration)
	_, err = e.NewIndex(util.SecsToTime(5), 5)
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, e) // save e3
	require.NoError(t, err)
	// r4, e4
	r.Indices = r.Indices[:1]
	r.Indices[0].Expiration = util.SecsToTime(6)
	e.Indices[0].Token.ExpirationTick = reservation.TickFromTime(e.Indices[0].Expiration)
	err = db.NewSegmentRsv(ctx, r) // save r4
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.Indices = e.Indices[:1]
	e.Indices[0].Expiration = util.SecsToTime(5)
	e.Indices[0].Token.ExpirationTick = reservation.TickFromTime(e.Indices[0].Expiration)
	e.ID.ASID = xtest.MustParseAS("ff00:0:4")
	e.SegmentReservations = []*segment.Reservation{r}
	err = db.PersistE2ERsv(ctx, e) // save e4
	require.NoError(t, err)
	// e5
	e.ID.ASID = xtest.MustParseAS("ff00:0:5")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(1000)
	e.Indices[0].Token.ExpirationTick = reservation.TickFromTime(e.Indices[0].Expiration)
	err = db.PersistE2ERsv(ctx, e) // save e5
	require.NoError(t, err)

	// second 1: nothing deleted
	c, err := db.DeleteExpiredIndices(ctx, util.SecsToTime(1))
	require.NoError(t, err)
	require.Equal(t, 0, c)
	rsvs, err := db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress) // get all seg rsvs
	require.NoError(t, err)
	require.Len(t, rsvs, 4)
	e2es := getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 5)
	// second 2, in DB: r1...r2,r3...e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(2))
	require.NoError(t, err)
	require.Equal(t, 1, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 4)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 4)
	// second 3: in DB: r2,r3...e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(3))
	require.NoError(t, err)
	require.Equal(t, 1, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 3)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 4)
	// second 4: in DB: e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(4))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 3) // r2 is gone, cascades for e2
	// second 5: in DB: e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(5))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 3)
	// second 6: in DB: r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(6))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 1)
	// second 7, in DB: nothing
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(7))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 0)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 0) // r4 is gone, cascades for e5
}

func testNextExpirationTime(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()

	// empty
	exp, err := db.NextExpirationTime(ctx)
	require.NoError(t, err)
	require.True(t, exp.IsZero())

	t1 := util.SecsToTime(111)
	r := st.NewRsv(st.WithID("ff00:0:1", "00000001"), st.AddIndex(0,
		st.WithExpiration(t1)), st.WithPath("1-ff00:0:1", 1, 1, "1-ff00:0:2"))
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)

	exp, err = db.NextExpirationTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t1, exp)

	// add an E2E index that will expire later
	re2e := &e2e.Reservation{
		ID: reservation.ID{
			ASID:   xtest.MustParseAS("ff00:0:1"),
			Suffix: make([]byte, reservation.IDSuffixE2ELen),
		},
		SegmentReservations: []*segment.Reservation{r},
	}
	t2 := t1.Add(time.Second)
	_, err = re2e.NewIndex(t2, 5)
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, re2e)
	require.NoError(t, err)

	exp, err = db.NextExpirationTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t1, exp)

	// the E2E index will expire earlier
	err = db.DeleteE2ERsv(ctx, &re2e.ID)
	require.NoError(t, err)
	re2e = &e2e.Reservation{
		ID: reservation.ID{
			ASID:   xtest.MustParseAS("ff00:0:1"),
			Suffix: make([]byte, reservation.IDSuffixE2ELen),
		},
		SegmentReservations: []*segment.Reservation{r},
	}
	t3 := t1.Add(-time.Second)
	_, err = re2e.NewIndex(t3, 5)
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, re2e)
	require.NoError(t, err)

	exp, err = db.NextExpirationTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t3, exp)
}

func testPersistE2ERsv(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	r1 := newTestE2EReservation(t)
	for _, seg := range r1.SegmentReservations {
		err := db.PersistSegmentRsv(ctx, seg)
		require.NoError(t, err)
	}
	err := db.PersistE2ERsv(ctx, r1)
	require.NoError(t, err)
	// get it back
	rsv, err := db.GetE2ERsvFromID(ctx, &r1.ID)
	require.NoError(t, err)
	require.Equal(t, r1, rsv)
	// modify
	r2 := rsv
	for i := range r2.ID.Suffix {
		r2.ID.Suffix[i] = byte(i)
	}
	for i := uint32(2); i < 16; i++ { // add 14 more indices
		_, err = r2.NewIndex(util.SecsToTime(i), 5)
		require.NoError(t, err)
	}
	for i := 0; i < 2; i++ {
		seg := newTestReservation(t)
		seg.ID.ASID = xtest.MustParseAS(fmt.Sprintf("ff00:2:%d", i+1))
		for j := uint32(1); j < 16; j++ {
			_, err := seg.NewIndex(reservation.IndexNumber(j), util.SecsToTime(j), 1, 3, 2, 5,
				reservation.CorePath)
			require.NoError(t, err)
		}
		err := db.PersistSegmentRsv(ctx, seg)
		require.NoError(t, err)
		r2.SegmentReservations = append(r2.SegmentReservations, seg)
	}
	err = db.PersistE2ERsv(ctx, r2)
	require.NoError(t, err)
	rsv, err = db.GetE2ERsvFromID(ctx, &r2.ID)
	require.NoError(t, err)
	require.Equal(t, r2, rsv)
	// check the other reservation was left intact
	rsv, err = db.GetE2ERsvFromID(ctx, &r1.ID)
	require.NoError(t, err)
	require.Equal(t, r1, rsv)
	// try to persist an e2e reservation without persisting its associated segment reservation
	r := newTestE2EReservation(t)
	r.SegmentReservations[0].ID.ASID = xtest.MustParseAS("ff00:3:1")
	err = db.PersistE2ERsv(ctx, r)
	require.Error(t, err)
	// after persisting the segment one, it will work
	err = db.PersistSegmentRsv(ctx, r.SegmentReservations[0])
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
}

func testGetAllE2ERsvs(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()

	r1 := newTestE2EReservation(t)
	for _, seg := range r1.SegmentReservations {
		err := db.PersistSegmentRsv(ctx, seg)
		require.NoError(t, err)
	}
	err := db.PersistE2ERsv(ctx, r1)
	require.NoError(t, err)
	// get it back
	rsvs, err := db.GetAllE2ERsvs(ctx)
	require.NoError(t, err)
	require.Len(t, rsvs, 1)
	require.Equal(t, []*e2e.Reservation{r1}, rsvs)
}

func testGetE2ERsvFromID(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	// create several e2e reservations, with one segment reservations in common, and two not
	checkThisRsvs := map[int]*e2e.Reservation{1: nil, 16: nil, 50: nil, 100: nil}
	for i := 1; i <= 100; i++ {
		r := newTestE2EReservation(t)
		r.ID.Suffix = make([]byte, reservation.IDSuffixSegLen)
		binary.BigEndian.PutUint32(r.ID.Suffix, uint32(i))
		_, found := checkThisRsvs[i]
		if found {
			checkThisRsvs[i] = r
		}
		for j := 0; j < 2; j++ {
			seg := newTestReservation(t)
			seg.ID.ASID = xtest.MustParseAS(fmt.Sprintf("ff00:%d:%d", i, j+1))
			err := db.PersistSegmentRsv(ctx, seg)
			require.NoError(t, err)
		}
		for _, seg := range r.SegmentReservations {
			segRsv, err := db.GetSegmentRsvFromID(ctx, &seg.ID)
			require.NoError(t, err)
			if segRsv == nil {
				err := db.PersistSegmentRsv(ctx, seg)
				require.NoError(t, err)
			}
		}
		err := db.PersistE2ERsv(ctx, r)
		require.NoError(t, err)
	}
	// now check
	for i, r := range checkThisRsvs {
		ID := reservation.ID{
			ASID:   xtest.MustParseAS("ff00:0:1"),
			Suffix: make([]byte, reservation.IDSuffixSegLen),
		}
		binary.BigEndian.PutUint32(ID.Suffix, uint32(i))
		rsv, err := db.GetE2ERsvFromID(ctx, &ID)
		require.NoError(t, err)
		require.Equal(t, r, rsv)
	}
	// with 8 indices starting at index number 14
	r := newTestE2EReservation(t)
	r.Indices = e2e.Indices{}
	for i := uint32(2); i < 18; i++ {
		_, err := r.NewIndex(util.SecsToTime(i/2), 5)
		require.NoError(t, err)
	}
	r.Indices = r.Indices[14:]
	for i := uint32(18); i < 20; i++ {
		_, err := r.NewIndex(util.SecsToTime(i/2), 5)
		require.NoError(t, err)
	}
	err := db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
	rsv, err := db.GetE2ERsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// 16 indices
	require.Len(t, r.Indices, 4)
	for i := uint32(20); i < 32; i++ {
		_, err := r.NewIndex(util.SecsToTime(i/2), 5)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 16)
	err = db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetE2ERsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// not present in DB
	ID, err := reservation.NewID(xtest.MustParseAS("ff00:2222:3333"),
		xtest.MustParseHexString("0123456789abcdef01234567"))
	require.NoError(t, err)
	rsv, err = db.GetE2ERsvFromID(ctx, ID)
	require.NoError(t, err)
	require.Nil(t, rsv)

	require.Len(t, r.ID.Suffix, reservation.IDSuffixE2ELen)
	rand.Read(r.ID.Suffix)
	t.Logf("Retrieving ID %s", r.ID)
	err = db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
	r2, err := db.GetE2ERsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
}

func testGetE2ERsvsOnSegRsv(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	s1 := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, s1)
	require.NoError(t, err)
	s2 := newTestReservation(t)
	err = db.NewSegmentRsv(ctx, s2)
	require.NoError(t, err)
	// e2e reservations
	e1 := newTestE2EReservation(t)
	e1.ID.ASID = xtest.MustParseAS("ff00:0:1")
	e1.SegmentReservations = []*segment.Reservation{s1}
	err = db.PersistE2ERsv(ctx, e1)
	require.NoError(t, err)
	e2 := newTestE2EReservation(t)
	e2.ID.ASID = xtest.MustParseAS("ff00:0:2")
	e2.SegmentReservations = []*segment.Reservation{s2}
	err = db.PersistE2ERsv(ctx, e2)
	require.NoError(t, err)
	e3 := newTestE2EReservation(t)
	e3.ID.ASID = xtest.MustParseAS("ff00:0:3")
	e3.SegmentReservations = []*segment.Reservation{s1, s2}
	err = db.PersistE2ERsv(ctx, e3)
	require.NoError(t, err)
	// test
	rsvs, err := db.GetE2ERsvsOnSegRsv(ctx, &s1.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, rsvs, []*e2e.Reservation{e1, e3})
	rsvs, err = db.GetE2ERsvsOnSegRsv(ctx, &s2.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, rsvs, []*e2e.Reservation{e2, e3})
}

func testAddToAdmissionList(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	futureTS := util.SecsToTime(1)
	thisHost := net.ParseIP("127.0.0.1")
	regexpIA := ""
	regexpHost := ""
	err := db.AddToAdmissionList(ctx, futureTS, thisHost, regexpIA, regexpHost, true)
	require.NoError(t, err)

	regexpIA = "\\"
	err = db.AddToAdmissionList(ctx, futureTS, thisHost, regexpIA, regexpHost, true)
	require.Error(t, err)

	regexpIA = ""
	regexpHost = "\\"
	err = db.AddToAdmissionList(ctx, futureTS, thisHost, regexpIA, regexpHost, true)
	require.Error(t, err)
}

func testCheckAdmissionList(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	type Entry struct {
		dstEndhost string
		validuntil time.Time
		regexpIA   string
		regexpHost string
		allowed    bool
	}
	cases := map[string]struct {
		entries     []Entry
		currentTime time.Time
		dstEndhost  string
		srcIA       string
		srcHost     string

		expectFailure   bool
		expectNoEntries bool
		allowed         bool
	}{
		"empty": {
			entries:         []Entry{},
			currentTime:     util.SecsToTime(1),
			dstEndhost:      "1.1.1.1",
			srcIA:           "1-ff00:0:111",
			srcHost:         "1.2.3.4",
			expectNoEntries: true,
		},
		"one_rule_accepting": {
			entries: []Entry{
				{
					dstEndhost: "1.1.1.1",
					validuntil: util.SecsToTime(20),
					regexpIA:   "", // equivalent to .*
					regexpHost: "",
					allowed:    true,
				},
			},
			currentTime: util.SecsToTime(10),
			dstEndhost:  "1.1.1.1",
			srcIA:       "1-ff00:0:111",
			srcHost:     "1.2.3.4",
			allowed:     true,
		},
		"expired_rule": {
			entries: []Entry{
				{
					dstEndhost: "1.1.1.1",
					validuntil: util.SecsToTime(10),
					regexpIA:   "",
					regexpHost: "",
					allowed:    true,
				},
			},
			currentTime:     util.SecsToTime(11),
			dstEndhost:      "1.1.1.1",
			srcIA:           "1-ff00:0:111",
			srcHost:         "1.2.3.4",
			expectNoEntries: true,
		},
		"match_only_ia": {
			entries: []Entry{
				{
					dstEndhost: "1.1.1.1",
					validuntil: util.SecsToTime(20),
					regexpIA:   ".*",
					regexpHost: "2.2.2.2",
					allowed:    true,
				},
			},
			currentTime:     util.SecsToTime(11),
			dstEndhost:      "1.1.1.1",
			srcIA:           "1-ff00:0:111",
			srcHost:         "1.2.3.4",
			expectNoEntries: true,
		},
		"whitelist_everything,_blacklist_host": {
			entries: []Entry{
				{
					dstEndhost: "1.1.1.1",
					validuntil: util.SecsToTime(20),
					regexpIA:   "",
					regexpHost: "",
					allowed:    true,
				},
				{
					dstEndhost: "1.1.1.1",
					validuntil: util.SecsToTime(19), // newer -> higher priority
					regexpIA:   "",
					regexpHost: "1.2.3.4",
					allowed:    false,
				},
			},
			currentTime: util.SecsToTime(11),
			dstEndhost:  "1.1.1.1",
			srcIA:       "1-ff00:0:111",
			srcHost:     "1.2.3.4",
			allowed:     false,
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db := newDB()
			for _, entry := range tc.entries {
				err := db.AddToAdmissionList(ctx, entry.validuntil, net.ParseIP(entry.dstEndhost),
					entry.regexpIA, entry.regexpHost, entry.allowed)
				require.NoError(t, err)
			}
			res, err := db.CheckAdmissionList(ctx, tc.currentTime, net.ParseIP(tc.dstEndhost),
				xtest.MustParseIA(tc.srcIA), tc.srcHost)
			if tc.expectFailure {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			switch {
			case tc.expectNoEntries:
				require.Equal(t, 0, res)
			case tc.allowed:
				require.Greater(t, res, 0)
			case !tc.allowed:
				require.Less(t, res, 0)
			}
		})
	}
}

func testGetInterfaceUsage(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	// empty
	testInterfaceUseIngress(ctx, t, db, 0, 0)
	testInterfaceUseEgress(ctx, t, db, 1, 0)
	// add a reservation 0->1  bwcls 2:
	rsv := newTestReservation(t)
	ID1 := rsv.ID
	err := db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)
	testInterfaceUseIngress(ctx, t, db, 0, toKbps(2))
	testInterfaceUseEgress(ctx, t, db, 1, toKbps(2))
	// add a reservation 0->2 bwcls 3:
	rsv = newTestReservation(t)
	rsv.ID.Suffix[0]++
	rsv.Egress = 2
	rsv.Indices[0].AllocBW, rsv.Indices[0].MaxBW, rsv.Indices[0].Token.InfoField.BWCls = 3, 3, 3
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)
	testInterfaceUseIngress(ctx, t, db, 0, toKbps(2)+toKbps(3))
	testInterfaceUseEgress(ctx, t, db, 1, toKbps(2))
	testInterfaceUseEgress(ctx, t, db, 2, toKbps(3))
	// add an index bwcls 9
	_, err = rsv.NewIndex(1, util.SecsToTime(2), 1, 9, 9, 1, reservation.CorePath)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)
	testInterfaceUseIngress(ctx, t, db, 0, toKbps(2)+toKbps(9))
	testInterfaceUseEgress(ctx, t, db, 1, toKbps(2))
	testInterfaceUseEgress(ctx, t, db, 2, toKbps(9))
	// remove the first index in 0->2 bwcls 3:
	err = rsv.RemoveIndex(0)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)
	testInterfaceUseIngress(ctx, t, db, 0, toKbps(2)+toKbps(9))
	testInterfaceUseEgress(ctx, t, db, 1, toKbps(2))
	testInterfaceUseEgress(ctx, t, db, 2, toKbps(9))
	// remove reservation 0->1 bwcls 2:
	err = db.DeleteSegmentRsv(ctx, &ID1)
	require.NoError(t, err)
	testInterfaceUseIngress(ctx, t, db, 0, toKbps(9))
	testInterfaceUseEgress(ctx, t, db, 1, 0)
	testInterfaceUseEgress(ctx, t, db, 2, toKbps(9))
}

func testStatefulTables(ctx context.Context, t *testing.T, newDB func() backend.DB) {
	db := newDB()
	rsv := newTestReservation(t)
	// empty interface usage tables
	bw, err := db.GetInterfaceUsageIngress(ctx, rsv.Ingress)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	bw, err = db.GetInterfaceUsageEgress(ctx, rsv.Egress)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	// insert a reservation
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)
	bw, err = db.GetInterfaceUsageIngress(ctx, rsv.Ingress)
	require.NoError(t, err)
	require.Equal(t, rsv.MaxBlockedBW(), bw)
	bw, err = db.GetInterfaceUsageEgress(ctx, rsv.Egress)
	require.NoError(t, err)
	require.Equal(t, rsv.MaxBlockedBW(), bw)
	// cleanup everything, leave empty tables again
	err = db.DeleteSegmentRsv(ctx, &rsv.ID)
	require.NoError(t, err)
	bw, err = db.GetInterfaceUsageIngress(ctx, rsv.Ingress)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	bw, err = db.GetInterfaceUsageEgress(ctx, rsv.Egress)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	// empty tables again
	bw, err = db.GetTransitDem(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	bw, err = db.GetTransitAlloc(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	bw, bw2, err := db.GetSourceState(ctx, rsv.ID.ASID, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	require.Equal(t, uint64(0), bw2)
	bw, err = db.GetInDemand(ctx, rsv.ID.ASID, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	bw, err = db.GetEgDemand(ctx, rsv.ID.ASID, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(0), bw)
	// persist transit dem
	err = db.PersistTransitDem(ctx, 1, 2, 42)
	require.NoError(t, err)
	bw, err = db.GetTransitDem(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(42), bw)
	// persist transit alloc
	err = db.PersistTransitAlloc(ctx, 1, 2, 43)
	require.NoError(t, err)
	bw, err = db.GetTransitAlloc(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(43), bw)
	// persist source state
	err = db.PersistSourceState(ctx, rsv.ID.ASID, 1, 2, 44, 45)
	require.NoError(t, err)
	bw, bw2, err = db.GetSourceState(ctx, rsv.ID.ASID, 1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(44), bw)
	require.Equal(t, uint64(45), bw2)
	// persist in demand
	err = db.PersistInDemand(ctx, rsv.ID.ASID, 1, 46)
	require.NoError(t, err)
	bw, err = db.GetInDemand(ctx, rsv.ID.ASID, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(46), bw)
	// persist eg demand
	err = db.PersistEgDemand(ctx, rsv.ID.ASID, 2, 47)
	require.NoError(t, err)
	bw, err = db.GetEgDemand(ctx, rsv.ID.ASID, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(47), bw)
}

// newToken just returns a token that can be serialized. This one has two HopFields.
func newToken() *reservation.Token {
	t, err := reservation.TokenFromRaw(xtest.MustParseHexString(
		"0000000000040500003f001002bad1ce003f001002facade"))
	if err != nil {
		panic("invalid serialized token")
	}
	return t
}

func newTestReservation(t *testing.T) *segment.Reservation {
	var err error
	t.Helper()
	r := segment.NewReservation(xtest.MustParseAS("ff00:0:1"))
	//only set so that validate does not panic
	p := test.NewSnetPath("1-ff00:0:1", 1, 1, "1-ff00:0:2")
	r.Steps, err = base.StepsFromSnet(p)
	if err != nil {
		panic(err)
	}
	r.RawPath, err = base.PathFromDataplanePath(p.Dataplane())
	if err != nil {
		panic(err)
	}
	r.Ingress = 0
	r.Egress = 1
	r.TrafficSplit = 3
	r.PathEndProps = reservation.EndLocal | reservation.StartLocal
	expTime := util.SecsToTime(1)
	_, err = r.NewIndex(0, expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	err = r.SetIndexConfirmed(0)
	require.NoError(t, err)
	err = r.SetIndexActive(0)
	require.NoError(t, err)
	return r
}

func newTestE2EReservation(t *testing.T) *e2e.Reservation {
	rsv := &e2e.Reservation{
		ID: reservation.ID{
			ASID:   xtest.MustParseAS("ff00:0:1"),
			Suffix: make([]byte, reservation.IDSuffixE2ELen),
		},
		SegmentReservations: []*segment.Reservation{
			newTestReservation(t),
		},
		Steps: make(base.PathSteps, 0),
	}
	expTime := util.SecsToTime(1)
	_, err := rsv.NewIndex(expTime, 5)
	require.NoError(t, err)
	return rsv
}

func getAllE2ERsvsOnSegmentRsvs(ctx context.Context, t *testing.T, db backend.DB,
	ids []reservation.ID) []*e2e.Reservation {

	set := make(map[string]struct{})
	rsvs := make([]*e2e.Reservation, 0)
	for _, id := range ids {
		rs, err := db.GetE2ERsvsOnSegRsv(ctx, &id)
		require.NoError(t, err)
		for _, r := range rs {
			s := hex.EncodeToString(r.ID.ToRaw())
			_, found := set[s]
			if !found {
				rsvs = append(rsvs, r)
				set[s] = struct{}{}
			}
		}
	}
	return rsvs
}

func testInterfaceUseIngress(ctx context.Context, t *testing.T, db backend.DB,
	ifid uint16, expected uint64) {

	use, err := db.GetInterfaceUsageIngress(ctx, ifid)
	require.NoError(t, err)
	require.Equal(t, expected, use)
}

func testInterfaceUseEgress(ctx context.Context, t *testing.T, db backend.DB,
	ifid uint16, expected uint64) {

	use, err := db.GetInterfaceUsageEgress(ctx, ifid)
	require.NoError(t, err)
	require.Equal(t, expected, use)
}

func toKbps(bwcls reservation.BWCls) uint64 {
	return bwcls.ToKbps()
}
