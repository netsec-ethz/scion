// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file contains an SQLite backend for the PathDB.

package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/hummingbirddb"
	"github.com/scionproto/scion/private/storage/db"
)

var _ hummingbirddb.DB = (*Backend)(nil)

type Backend struct {
	db *sql.DB
	*executor
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, serrors.WrapStr("opening db", err, "schema", Schema)
	}
	return &Backend{
		executor: &executor{
			db: db,
		},
		db: db,
	}, nil
}

func (b *Backend) Close() error {
	return b.db.Close()
}

func (b *Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}
func (b *Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

func (b *Backend) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (hummingbirddb.Transaction, error) {

	b.Lock()
	defer b.Unlock()
	tx, err := b.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, serrors.WrapStr("Failed to create transaction", err)
	}
	return &transaction{
		executor: &executor{
			db: tx,
		},
		tx: tx,
	}, nil
}

var _ (hummingbirddb.Transaction) = (*transaction)(nil)

type transaction struct {
	*executor
	tx *sql.Tx
}

func (tx *transaction) Commit() error {
	tx.Lock()
	defer tx.Unlock()
	return tx.tx.Commit()
}

func (tx *transaction) Rollback() error {
	tx.Lock()
	defer tx.Unlock()
	return tx.tx.Rollback()
}

var _ (hummingbirddb.ReadWrite) = (*executor)(nil)

type executor struct {
	sync.RWMutex
	db db.Sqler
}

type IASet map[addr.IA]struct{}

func (e *executor) GetFlyovers(ctx context.Context, IAs []addr.IA) ([]*hummingbird.Flyover, error) {
	var flyovers []*hummingbird.Flyover
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		flyovers, err = getFlyovers(ctx, tx, IAs)
		return err
	})
	return flyovers, err
}

func (e *executor) StoreFlyovers(ctx context.Context, flyovers []*hummingbird.Flyover,
) error {

	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		return storeFlyovers(ctx, tx, flyovers)
	})
	return err
}

func (e *executor) DeleteExpiredFlyovers(ctx context.Context) (n int, err error) {
	return e.deleteExpiredFlyovers(ctx, time.Now())
}

func (e *executor) deleteExpiredFlyovers(
	ctx context.Context,
	notAfter time.Time,
) (n int, err error) {

	db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		n, err = deleteExpired(ctx, tx, notAfter)
		return err
	})
	// n and err have been already set in the closure, just return.
	return
}

func getFlyovers(ctx context.Context, tx *sql.Tx, IAs []addr.IA) ([]*hummingbird.Flyover, error) {
	query := "SELECT ia,ingress,egress,resID,bw,notBefore,notAfter,ak FROM flyovers"
	queryParams := []any{}
	// If there are any parameters, format them for SQL.
	if len(IAs) > 0 {
		query += " WHERE IA in (" +
			strings.Repeat("?,", len(IAs)-1)
		query += "?)"
		for _, ia := range IAs {
			queryParams = append(queryParams, uint64(ia))
		}
	}
	// Query with or without query parameters.
	rows, err := tx.QueryContext(ctx, query, queryParams...)
	if err != nil {
		return nil, serrors.WrapStr("looking for flyovers in DB", err, "q", query)
	}
	flyovers := make([]*hummingbird.Flyover, 0)
	for rows.Next() {
		var ia uint64
		var ingress uint16
		var egress uint16
		var resID uint32
		var bw uint16
		var notBefore uint32
		var notAfter uint32
		var ak []byte
		if err := rows.Scan(&ia, &ingress, &egress, &resID, &bw, &notBefore, &notAfter,
			&ak); err != nil {

			return nil, serrors.WrapStr("error reading flyover from DB", err)
		}
		// Convert ak from slice to array.
		var akArray [16]byte
		copy(akArray[:], ak)
		// Add the flyover.
		flyovers = append(flyovers, &hummingbird.Flyover{
			BaseHop: hummingbird.BaseHop{
				IA:      addr.IA(ia),
				Ingress: ingress,
				Egress:  egress,
			},
			ResID:     resID,
			Bw:        bw,
			StartTime: notBefore,
			Duration:  uint16(notAfter - notBefore),
			Ak:        akArray,
		})
	}
	return flyovers, nil
}

func storeFlyovers(
	ctx context.Context,
	tx *sql.Tx,
	flyovers []*hummingbird.Flyover,
) error {

	const numCols = 8                                         // 8 columns
	rowParams := "(" + strings.Repeat("?,", numCols-1) + "?)" // => (?,?,?,?,?,?,?,?)
	// query has the form:
	//	INSERT INTO flyovers  (ia,ingress,egress,resID,bw,notBefore,notAfter,ak) VALUES
	//	(?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?)
	// for a total of number of flyovers.
	query := "INSERT INTO flyovers (ia,ingress,egress,resID,bw,notBefore,notAfter,ak) VALUES " +
		strings.Repeat(rowParams+",", len(flyovers)-1) + rowParams

	params := make([]any, 0, len(flyovers)*numCols)
	for _, f := range flyovers {
		params = append(params,
			uint64(f.IA),
			uint16(f.Ingress),
			uint16(f.Egress),
			uint32(f.ResID),
			uint16(f.Bw),
			f.StartTime,
			f.StartTime+uint32(f.Duration),
			f.Ak[:],
		)
	}

	res, err := tx.ExecContext(ctx, query, params...)
	if err != nil {
		return serrors.WrapStr("storing flyovers", err, "query", query)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return serrors.WrapStr("checking inserted flyovers, cannot retrieve num. affected rows",
			err)
	}
	if int(n) != len(flyovers) {
		return serrors.New("storing flyovers: affected rows differs from request",
			"affected", n, "requested", len(flyovers))
	}
	return nil
}

func deleteExpired(ctx context.Context, tx *sql.Tx, now time.Time) (int, error) {
	query := "DELETE FROM flyovers WHERE notAfter < ?"
	res, err := tx.ExecContext(ctx, query, now.Unix())
	if err != nil {
		return 0, serrors.WrapStr("deleting expired flyovers", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, serrors.WrapStr("computing affected expired flyovers", err)
	}
	return int(n), nil
}
