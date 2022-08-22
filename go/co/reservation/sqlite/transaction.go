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

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// phoenixTx will recreate itself if the promotion from read-transaction to write-transaction
// incurs in a busy error.
// A busy error happens in sqlite3 when a read-transaction tries to be promoted to a
// write-transaction, but there exists already a write-transaction that has not finished yet.
type phoenixTx struct {
	*executor

	createNewTx func() (*sql.Tx, error)
	txList      []*sql.Tx
	attempts    int           // to obtain a write-tx per statement if current tx is busy
	sleepDur    time.Duration // between attempts
}

var _ backend.Transaction = (*phoenixTx)(nil)

// NewTransaction creates a new transaction that works with sqlite and is able to retry to
// obtain a write-transaction even when busy.
// The resurrectionAttempts indicates how many times the phoenixTx will try to obtain a
// new transaction if the current one failed to promote to write-tx with busy error.
// The sleepDuration specifies the time for which it sleeps between resurrection attempts.
// Note than when obtaining a new transaction, read operations may not be consistent anymore,
// so that non-repeatable reads can occur.
// Note than this transaction _should_ be atomic, in that there won't be any other
// connection able to get the write lock until this transaction finishes.
// See also https://en.wikipedia.org/wiki/Isolation_(database_systems)#Non-repeatable_reads
func NewTransaction(ctx context.Context, createTxFun func() (*sql.Tx, error),
	resurrectionAttempts int, sleepDuration time.Duration) (backend.Transaction, error) {

	tx, err := createTxFun()
	if err != nil {
		return nil, serrors.WrapStr("creating transaction", err)
	}
	// because transactions in sqlite are deferred until first sql instruction, SELECT something
	// now just to force to begin the read-transaction at this point
	rows, err := tx.QueryContext(ctx, "SELECT 0 FROM e2e_index WHERE ROWID = -1")
	defer rows.Close()
	if err == nil {
		for rows.Next() { // we actually need to call Next()
		}
		if rows.Err() != nil {
			return nil, rows.Err()
		}
	}
	return &phoenixTx{
		executor: &executor{
			db: tx,
		},
		createNewTx: createTxFun,
		txList:      []*sql.Tx{tx},
		attempts:    resurrectionAttempts,
		sleepDur:    sleepDuration,
	}, nil
}

// Tx returns the current transaction. Note that t.txList[len(txList)-1] == t.executor.db
func (t *phoenixTx) Tx() *sql.Tx {
	return t.executor.db.(*sql.Tx)
}

func (t *phoenixTx) ReplaceTx(tx *sql.Tx) {
	t.txList = append(t.txList, tx)
	t.executor.db = tx
}

func (t *phoenixTx) Commit() error {
	for _, tx := range t.txList {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (t *phoenixTx) Rollback() error {
	var errs serrors.List
	for _, tx := range t.txList {
		err := tx.Rollback()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs.ToError()
}

func (t *phoenixTx) NewSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	return t.tryHard(func() error {
		return t.executor.NewSegmentRsv(ctx, rsv)
	})
}

func (t *phoenixTx) PersistSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	return t.tryHard(func() error {
		return t.executor.PersistSegmentRsv(ctx, rsv)
	})
}

func (t *phoenixTx) DeleteSegmentRsv(ctx context.Context, ID *reservation.ID) error {
	return t.tryHard(func() error {
		return t.executor.DeleteSegmentRsv(ctx, ID)
	})
}

func (t *phoenixTx) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, error) {
	var n int
	var err error
	err = t.tryHard(func() error {
		n, err = t.executor.DeleteExpiredIndices(ctx, now)
		return err
	})
	return n, err
}

func (t *phoenixTx) PersistE2ERsv(ctx context.Context, rsv *e2e.Reservation) error {
	return t.tryHard(func() error {
		return t.executor.PersistE2ERsv(ctx, rsv)
	})
}

func (t *phoenixTx) DeleteE2ERsv(ctx context.Context, ID *reservation.ID) error {
	return t.tryHard(func() error {
		return t.executor.DeleteE2ERsv(ctx, ID)
	})
}

func (t *phoenixTx) AddToAdmissionList(ctx context.Context, validUntil time.Time,
	dstEndhost net.IP, regexpIA, regexpHost string, allowAdmission bool) error {
	return t.tryHard(func() error {
		return t.executor.AddToAdmissionList(ctx, validUntil, dstEndhost,
			regexpIA, regexpHost, allowAdmission)
	})
}

func (t *phoenixTx) DeleteExpiredAdmissionEntries(ctx context.Context, now time.Time) (int, error) {
	var n int
	var err error
	err = t.tryHard(func() error {
		n, err = t.executor.DeleteExpiredAdmissionEntries(ctx, now)
		return err
	})
	return n, err
}

func (t *phoenixTx) PersistTransitDem(ctx context.Context, ingress, egress uint16,
	transit uint64) error {

	return t.tryHard(func() error {
		return t.executor.PersistTransitDem(ctx, ingress, egress, transit)
	})
}

func (t *phoenixTx) PersistTransitAlloc(ctx context.Context, ingress, egress uint16,
	transit uint64) error {

	return t.tryHard(func() error {
		return t.executor.PersistTransitAlloc(ctx, ingress, egress, transit)
	})
}

func (t *phoenixTx) PersistSourceState(ctx context.Context, source addr.AS, ingress, egress uint16,
	srcDem, srcAlloc uint64) error {

	return t.tryHard(func() error {
		return t.executor.PersistSourceState(ctx, source, ingress, egress, srcDem, srcAlloc)
	})
}

func (t *phoenixTx) PersistInDemand(ctx context.Context, source addr.AS, ingress uint16,
	demand uint64) error {
	return t.tryHard(func() error {
		return t.executor.PersistInDemand(ctx, source, ingress, demand)
	})
}

func (t *phoenixTx) PersistEgDemand(ctx context.Context, source addr.AS, egress uint16,
	demand uint64) error {

	return t.tryHard(func() error {
		return t.executor.PersistEgDemand(ctx, source, egress, demand)
	})
}

func (t *phoenixTx) tryHard(fun func() error) error {
	var err error
	for attempt := 0; attempt < t.attempts; attempt++ {
		err = fun()
		var sqlite3Err sqlite3.Error
		if errors.As(err, &sqlite3Err) && sqlite3Err.Code == sqlite3.ErrBusy {
			time.Sleep(t.sleepDur)
			tx, err := t.createNewTx()
			if err != nil {
				return err
			}
			t.ReplaceTx(tx)
		} else {
			return err
		}
	}
	return err
}
