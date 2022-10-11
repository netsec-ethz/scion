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

package sqlite

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/co/reservation/reservationdbtest"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/test"
	coltest "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestReservationDBSuite(t *testing.T) {
	reservationdbtest.TestDB(t, func() backend.DB { return newDB(t) })
}

func TestNewSegSuffix(t *testing.T) {
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	db := newDB(t)
	suffix, err := newSegSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(1), suffix)
	// add reservations
	addSegRsvRows(t, db, asid, 3, 5)
	suffix, err = newSegSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.False(t, isSuffixInDB(t, db, asid, suffix))
	addSegRsvRows(t, db, asid, 1, 2)
	suffix, err = newSegSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.False(t, isSuffixInDB(t, db, asid, suffix))
}

// TestTransactions checks that the read transactions have an independent and consistent view
// of the database, as if it had taken a snapshot of it when the transaction started.
// A read transaction is one that only performs SELECT operations.
// As soon as one read transaction does one write operation, it is promoted to a write transaction.
// See also https://www.sqlite.org/lang_transaction.html
func TestTransactions(t *testing.T) {
	var err error
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	db, removeF := newDBNotTemporary(t)
	defer removeF()
	defer func() {
		err := db.Close()
		require.NoError(t, err)
	}()

	// create a segment reservation
	rsv := segment.NewReservation(xtest.MustParseAS("ff00:0:111"))
	_, err = rsv.NewIndex(1, util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.NoError(t, err)

	rsv.Steps = test.NewSteps("1-ff00:0:1", 1, 1, "1-ff00:0:2")
	rsv.TransportPath = test.NewColPathMin(rsv.Steps)
	rsv.ID.Suffix[0]++
	// save the reservation to DB
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)

	// now open two transactions: tx1 and tx2. Tx1 will modify the reservation and save it, but
	// this will not affect the view of tx2, which will still see the old contents
	db.SetMaxOpenConns(2)
	tx1, err := db.BeginTransaction(ctx, nil)
	require.NoError(t, err)
	tx2, err := db.BeginTransaction(ctx, nil)
	require.NoError(t, err)

	rsv1, err := tx1.GetSegmentRsvFromID(ctx, &rsv.ID)
	require.NoError(t, err)
	require.Equal(t, 1, int(rsv1.Indices[0].MaxBW))
	rsv1.Indices[0].MaxBW++
	err = tx1.PersistSegmentRsv(ctx, rsv1)
	require.NoError(t, err)
	tx1.Commit()

	rsv2, err := tx2.GetSegmentRsvFromID(ctx, &rsv.ID)
	require.NoError(t, err)
	require.Equal(t, 1, int(rsv2.Indices[0].MaxBW))
	tx2.Commit()
}

// TestTransactionsBusy tests that we can use several transactions at the same time, and that
// the DB will retry to obtain a write-transaction when needed.
func TestTransactionsBusy(t *testing.T) {
	var err error
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	db, removeF := newDBNotTemporary(t)
	defer func() {
		err := db.Close()
		require.NoError(t, err)
		removeF()
	}()

	ID := coltest.MustParseID("ff00:0:111", "00000001")
	// create a segment reservation
	rsv := segment.NewReservation(ID.ASID)
	rsv.ID = *ID
	_, err = rsv.NewIndex(1, util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.NoError(t, err)
	// save the reservation to DB
	rsv.Steps = test.NewSteps("1-ff00:0:1", 1, 1, "1-ff00:0:2")
	rsv.TransportPath = test.NewColPathMin(rsv.Steps)
	err = db.PersistSegmentRsv(ctx, rsv)
	require.NoError(t, err)

	db.SetMaxOpenConns(2)

	// we need to ensure that we can read from many transactions, and that once we upgrade one
	// transaction to write-transaction, the other transactions cannot write and automatically
	// will retry for a period of time to obtain a write transaction.

	afterTxCreation := sync.WaitGroup{}
	afterTxCreation.Add(2)

	afterTx1Modifies := sync.WaitGroup{}
	afterTx1Modifies.Add(1)

	allDone := sync.WaitGroup{}
	allDone.Add(2)

	go func() { // TX1
		defer allDone.Done()

		tx1, err := db.BeginTransaction(ctx, nil)
		require.NoError(t, err)
		afterTxCreation.Done()
		afterTxCreation.Wait()
		t.Logf("TX1: got transaction at %s", time.Now().Format(time.StampMicro))

		// at this point, we have two concurrent read-transactions
		rsv1, err := tx1.GetSegmentRsvFromID(ctx, &rsv.ID)
		require.NoError(t, err)
		rsv1.ID.Suffix[0]++

		t.Logf("TX1: attempting to get a write-transaction at %s",
			time.Now().Format(time.StampMicro))
		err = tx1.PersistSegmentRsv(ctx, rsv1)
		require.NoError(t, err)
		afterTx1Modifies.Done()

		err = tx1.Commit()
		require.NoError(t, err)
	}()

	go func() { // TX2
		defer allDone.Done()

		tx2, err := db.BeginTransaction(ctx, nil)
		require.NoError(t, err)
		afterTxCreation.Done()
		afterTxCreation.Wait()
		t.Logf("TX2: got transaction at %s", time.Now().Format(time.StampMicro))

		// at this point, we have two concurrent read-transactions
		rsv2, err := tx2.GetSegmentRsvFromID(ctx, &rsv.ID)
		require.NoError(t, err)
		require.Equal(t, rsv.ID.Suffix[0], rsv2.ID.Suffix[0])
		afterTx1Modifies.Wait()

		rsv2, err = tx2.GetSegmentRsvFromID(ctx, &rsv.ID)
		require.NoError(t, err)
		require.Equal(t, rsv.ID.Suffix[0], rsv2.ID.Suffix[0])
		rsv2.ID.Suffix[0] += 2
		t.Logf("TX2: attempting to get a write-transaction at %s",
			time.Now().Format(time.StampMicro))
		err = tx2.PersistSegmentRsv(ctx, rsv2)
		require.NoError(t, err)

		err = tx2.Commit()
		require.NoError(t, err)
	}()

	// wait for test to finish
	allDone.Wait()
}

// TestRaceForSuffix checks that there are no problems trying to obtain a suffix for the same
// AS ID from different goroutines, even if using transactions.
// As we use sqlite3 per default, the default behavior is to have only 1 open connection.
// This makes impossible to have more than one running transaction at a time. In this case
// the DB access is serialized by the sqlite3 driver itself.
// If we manually allow more than 1 open connection, we can create more than 1 transaction
// at a time. The problem arises if we try to modify the same table from more than one
// transaction, because the driver will return with a "table locked" or "database locked".
func TestRaceForSuffix(t *testing.T) {
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	db := newDB(t)

	wg := sync.WaitGroup{}
	wg.Add(2)

	fcn := func(t *testing.T, rsv *segment.Reservation, m1, m2 *sync.Mutex) {
		tx, err := db.BeginTransaction(ctx, nil)
		require.NoError(t, err, "failed for rsv %s", rsv.ID.String())
		defer tx.Rollback()

		t.Logf("[%s] waiting on 1...", &rsv.ID)
		m1.Lock()
		defer m1.Unlock()
		t.Logf("[%s] woke up on 1...", &rsv.ID)

		err = tx.NewSegmentRsv(ctx, rsv)
		require.NoError(t, err, "failed for rsv %s", rsv.ID.String())

		t.Logf("[%s] waiting on 2...", &rsv.ID)
		m2.Lock()
		defer m2.Unlock()
		t.Logf("[%s] woke up on 2...", &rsv.ID)

		err = tx.Commit()
		require.NoError(t, err, "failed for rsv %s", rsv.ID.String())
		wg.Done()
	}

	mut1_1, mut1_2 := sync.Mutex{}, sync.Mutex{}
	mut2_1, mut2_2 := sync.Mutex{}, sync.Mutex{}
	lockAllMutexes := func() {
		mut1_1.Lock()
		mut1_2.Lock()
		mut2_1.Lock()
		mut2_2.Lock()
	}

	steps := test.NewSteps("1-ff00:0:1", 1, 1, "1-ff00:0:2")
	transportPath := test.NewColPathMin(steps)

	rsv1 := segment.Reservation{
		ID:      reservation.ID{ASID: asid, Suffix: []byte{1, 1, 1, 1}},
		Indices: segment.Indices{segment.Index{}},
		Steps:   steps, TransportPath: transportPath}
	rsv2 := segment.Reservation{
		ID:      reservation.ID{ASID: asid, Suffix: []byte{2, 2, 2, 2}},
		Indices: segment.Indices{segment.Index{}},
		Steps:   steps, TransportPath: transportPath}
	lockAllMutexes()

	go fcn(t, &rsv1, &mut1_1, &mut1_2)
	go fcn(t, &rsv2, &mut2_1, &mut2_2)

	t.Logf("rsv1: %v", rsv1.ID.String())
	t.Logf("rsv2: %v", rsv2.ID.String())
	mut1_1.Unlock()
	mut2_1.Unlock()
	mut2_2.Unlock()
	mut1_2.Unlock()
	wg.Wait()
	t.Logf("rsv1: %v", rsv1.ID.String())
	t.Logf("rsv2: %v", rsv2.ID.String())
	require.NotEqual(t, rsv1.ID.Suffix, rsv2.ID.Suffix)
}

func BenchmarkNewSuffix10K(b *testing.B)  { benchmarkNewSuffix(b, 10000) }
func BenchmarkNewSuffix100K(b *testing.B) { benchmarkNewSuffix(b, 100000) }
func BenchmarkNewSuffix1M(b *testing.B)   { benchmarkNewSuffix(b, 1000000) }

func newDB(t testing.TB) *Backend {
	t.Helper()
	db, err := New("file::memory:")
	require.NoError(t, err)
	return db
}

// newDBNotTemporary creates a non temporary sqlite database. Temporary or in-memory sqlite DBs
// have the limitation of not using more than one connection: it creates a new temporary database
// instead. See also https://www.sqlite.org/inmemorydb.html
// The function returns the DB object and a cleanup fuction that must be invoked before the
// end of the test (usually with defer).
func newDBNotTemporary(t testing.TB) (*Backend, func()) {
	t.Helper()
	f, err := ioutil.TempFile("", "colibri_db_test.*.db")
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	db, err := New("file:" + f.Name())
	require.NoError(t, err)
	return db, func() {
		os.Remove(f.Name())
		os.Remove(f.Name() + "-shm")
		os.Remove(f.Name() + "-wal")
	}
}

func addSegRsvRows(t testing.TB, b *Backend, asid addr.AS, firstSuffix, lastSuffix uint32) {
	t.Helper()
	ctx := context.Background()
	query := `INSERT INTO seg_reservation (id_as, id_suffix, ingress, egress, path_type, steps,
		current_step, transportPath, end_props, traffic_split, src_ia, dst_ia, active_index)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, -1)`
	for suffix := firstSuffix; suffix <= lastSuffix; suffix++ {
		_, err := b.db.ExecContext(ctx, query, asid, suffix, 0, 0, reservation.CorePath, nil,
			0, nil, 0, 0, nil, nil)
		require.NoError(t, err)
	}
}

func isSuffixInDB(t *testing.T, b *Backend, asid addr.AS, suffix uint32) bool {
	t.Helper()
	ctx := context.Background()
	query := `SELECT COUNT(*) FROM seg_reservation
	WHERE id_as = ? AND id_suffix = ?`
	var count int
	err := b.db.QueryRowContext(ctx, query, asid, suffix).Scan(&count)
	require.NoError(t, err)
	return count > 0
}

func benchmarkNewSuffix(b *testing.B, entries uint32) {
	db := newDB(b)
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	addSegRsvRows(b, db, asid, 1, entries)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		suffix, err := newSegSuffix(ctx, db.db, asid)
		require.NoError(b, err)
		require.Equal(b, entries+1, suffix)
	}
}
