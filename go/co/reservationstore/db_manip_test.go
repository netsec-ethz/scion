// Copyright 2021 ETH Zurich, Anapaya Systems
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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

// AddSegmentReservation adds `count` segment reservation ASID-newsuffix to `db`.
func AddSegmentReservation(t testing.TB, db backend.DB, ASID string, count int) {
	t.Helper()
	var err error
	ctx := context.Background()

	r := newTestSegmentReservation(t, ASID) // the suffix will be overwritten
	for i := 0; i < count; i++ {
		p := test.NewSnetPath("1-"+ASID, i, 1, "1-ff00:0:2")
		r.Steps, err = base.StepsFromSnet(p)
		require.NoError(t, err)
		r.TransportPath, err = base.PathFromDataplanePath(p.Dataplane())
		require.NoError(t, err)
		err = db.NewSegmentRsv(ctx, r)
		require.NoError(t, err, "iteration i = %d", i)
	}
}

// AddE2EReservation ads `count` E2E reservations to the DB.
func AddE2EReservation(t testing.TB, db backend.DB, ASID string, count int) {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < count; i++ {
		r := newTestE2EReservation(t, ASID)

		auxBuff := make([]byte, 8)
		binary.BigEndian.PutUint64(auxBuff, uint64(i+1))
		copy(r.ID.Suffix[len(r.ID.Suffix)-8:], auxBuff)
		for _, seg := range r.SegmentReservations {
			err := db.PersistSegmentRsv(ctx, seg)
			require.NoError(t, err)
		}
		err := db.PersistE2ERsv(ctx, r)
		require.NoError(t, err)
	}
}

type testCapacities struct {
	Cap    uint64
	Ifaces []uint16
}

var _ base.Capacities = (*testCapacities)(nil)

func (c *testCapacities) IngressInterfaces() []uint16           { return c.Ifaces }
func (c *testCapacities) EgressInterfaces() []uint16            { return c.Ifaces }
func (c *testCapacities) CapacityIngress(ingress uint16) uint64 { return c.Cap }
func (c *testCapacities) CapacityEgress(egress uint16) uint64   { return c.Cap }

// newTestSegmentReservation creates a segment reservation
func newTestSegmentReservation(t testing.TB, ASID string) *segment.Reservation {
	t.Helper()
	r := segment.NewReservation(xtest.MustParseAS(ASID))
	r.Ingress = 0
	r.Egress = 1
	r.TrafficSplit = 3
	r.PathEndProps = reservation.EndLocal | reservation.StartLocal
	expTime := util.SecsToTime(1)
	_, err := r.NewIndex(0, expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	err = r.SetIndexConfirmed(0)
	require.NoError(t, err)
	err = r.SetIndexActive(0)
	require.NoError(t, err)
	return r
}

// newTestE2EReservation adds an E2E reservation, that uses three segment reservations on
// ASID-00000001, ff00:2:2-00000002 and ff00:3:3-00000003 .
// The E2E reservation is transit on the first leg.
func newTestE2EReservation(t testing.TB, ASID string) *e2e.Reservation {
	t.Helper()

	rsv := &e2e.Reservation{
		ID: *e2eIDFromRaw(t, ASID, "000000000000000000000001"),
		SegmentReservations: []*segment.Reservation{
			newTestSegmentReservation(t, ASID),
		},
	}
	_, err := rsv.NewIndex(util.SecsToTime(1), 5)
	require.NoError(t, err)
	return rsv
}

func e2eIDFromRaw(t testing.TB, ASID, suffix string) *reservation.ID {
	t.Helper()
	ID, err := reservation.NewID(xtest.MustParseAS(ASID), xtest.MustParseHexString(suffix))
	require.NoError(t, err)
	require.True(t, ID.IsE2EID())
	return ID
}
