// Copyright 2019 ETH Zurich
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

package drkeydbsqlite

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

const (
	UnableToPrepareStmt = "Unable to prepare stmt"
	UnableToExecuteStmt = "Unable to execute stmt"
)

var _ drkey.DB = (*Backend)(nil)

// Backend implements a drkey DB with sqlite.
type Backend struct {
	db                          *sql.DB
	getLvl1SrcASesStmt          *sql.Stmt
	getValidLvl1SrcASesStmt     *sql.Stmt
	getDRKeyLvl1Stmt            *sql.Stmt
	insertDRKeyLvl1Stmt         *sql.Stmt
	removeOutdatedDRKeyLvl1Stmt *sql.Stmt
	getDRKeyLvl2Stmt            *sql.Stmt
	insertDRKeyLvl2Stmt         *sql.Stmt
	removeOutdatedDRKeyLvl2Stmt *sql.Stmt
}

// New creates a database and prepares all statements.
func New(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &Backend{
		db: db,
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			b.db.Close()
		}
	}()
	if b.getLvl1SrcASesStmt, err = b.db.Prepare(getLvl1SrcASes); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.getValidLvl1SrcASesStmt, err = b.db.Prepare(getValidLvl1SrcASes); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.getDRKeyLvl1Stmt, err = b.db.Prepare(getDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.insertDRKeyLvl1Stmt, err = b.db.Prepare(insertDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.removeOutdatedDRKeyLvl1Stmt, err = b.db.Prepare(removeOutdatedDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.getDRKeyLvl2Stmt, err = b.db.Prepare(getDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.insertDRKeyLvl2Stmt, err = b.db.Prepare(insertDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if b.removeOutdatedDRKeyLvl2Stmt, err = b.db.Prepare(removeOutdatedDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	return b, nil
}

// Close closes the database connection.
func (b *Backend) Close() error {
	return b.db.Close()
}

const getLvl1SrcASes = `
SELECT SrcIsdID as I, SrcASID as A FROM DRKeyLvl1
GROUP BY I, A
`

// GetLvl1SrcASes returns a list of distinct ASes seen in the SRC of a level 1 key
func (b *Backend) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	rows, err := b.getLvl1SrcASesStmt.QueryContext(ctx)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return nil, err
	}
	ases := []addr.IA{}
	for rows.Next() {
		var I, A int
		if err := rows.Scan(&I, &A); err != nil {
			return nil, common.NewBasicError("Cannot copy from SQL to memory", err)
		}
		ia := addr.IA{
			I: addr.ISD(I),
			A: addr.AS(A),
		}
		ases = append(ases, ia)
	}
	return ases, nil
}

const getValidLvl1SrcASes = `
SELECT SrcIsdID as I, SrcASID as A FROM DRKeyLvl1
WHERE EpochBegin <= ? AND ? < EpochEnd
GROUP BY I, A
`

// GetValidLvl1SrcASes returns a list of distinct IAs that have a still valid level 1 key
// If the level 1 key is still valid according to valTime, its src IA will be in the list
func (b *Backend) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	rows, err := b.getValidLvl1SrcASesStmt.QueryContext(ctx, valTime, valTime)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return nil, err
	}
	ases := []addr.IA{}
	for rows.Next() {
		var I, A int
		if err := rows.Scan(&I, &A); err != nil {
			return nil, common.NewBasicError("Cannot copy from SQL to memory", err)
		}
		ia := addr.IA{
			I: addr.ISD(I),
			A: addr.AS(A),
		}
		ases = append(ases, ia)
	}
	return ases, nil
}

// GetLvl1Count returns the number of rows in the level 1 table
func (b *Backend) GetLvl1Count() int64 {
	countRow := b.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM DRKeyLvl1;")
	var count int64
	countRow.Scan(&count)
	return count
}

const getDRKeyLvl1 = `
SELECT EpochBegin, EpochEnd, Key FROM DRKeyLvl1
WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetDRKeyLvl1 takes an pointer to a first level DRKey and a timestamp at which the DRKey should be
// valid and returns the corresponding first level DRKey.
func (b *Backend) GetDRKeyLvl1(ctx context.Context, key drkey.Lvl1Meta, valTime uint32) (drkey.Lvl1Key, error) {
	var epochBegin, epochEnd int
	var bytes common.RawBytes
	err := b.getDRKeyLvl1Stmt.QueryRowContext(ctx, key.SrcIA.I, key.SrcIA.A,
		key.DstIA.I, key.DstIA.A, valTime, valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return drkey.Lvl1Key{}, err
	}
	returningKey := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
			SrcIA: key.SrcIA,
			DstIA: key.DstIA,
		},
		DRKey: drkey.DRKey{Key: bytes},
	}
	return returningKey, nil
}

const insertDRKeyLvl1 = `
INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?)
`

// InsertDRKeyLvl1 inserts a first level DRKey and returns the number of affected rows.
func (b *Backend) InsertDRKeyLvl1(ctx context.Context, key drkey.Lvl1Key) (int64, error) {
	res, err := b.insertDRKeyLvl1Stmt.ExecContext(ctx, key.SrcIA.I, key.SrcIA.A, key.DstIA.I,
		key.DstIA.A, uint32(key.Epoch.Begin.Unix()), uint32(key.Epoch.End.Unix()), key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

const removeOutdatedDRKeyLvl1 = `
DELETE FROM DRKeyLvl1 WHERE ? >= EpochEnd
`

// RemoveOutdatedDRKeyLvl1 removes all expired first level DRKeys. I.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (b *Backend) RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := b.removeOutdatedDRKeyLvl1Stmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetLvl2Count returns the number of rows in the level 1 table
func (b *Backend) GetLvl2Count() int64 {
	countRow := b.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM DRKeyLvl2;")
	var count int64
	countRow.Scan(&count)
	return count
}

const getDRKeyLvl2 = `
SELECT EpochBegin, EpochEnd, Key
FROM DRKeyLvl2 WHERE Protocol=? AND Type=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetDRKeyLvl2 takes a source, destination and additional ISD-AS, a source, destination and
// additional host, and a timestamp at which the DRKey should be valid and
// returns a second level DRKey of the request type
func (b *Backend) GetDRKeyLvl2(ctx context.Context, key drkey.Lvl2Meta, valTime uint32) (drkey.Lvl2Key, error) {
	var epochBegin int
	var epochEnd int
	var bytes common.RawBytes

	err := b.getDRKeyLvl2Stmt.QueryRowContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost, valTime,
		valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return drkey.Lvl2Key{}, err
	}
	returningKey := drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  key.KeyType,
			Protocol: key.Protocol,
			Epoch:    drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
			SrcIA:    key.SrcIA,
			DstIA:    key.DstIA,
			SrcHost:  key.SrcHost,
			DstHost:  key.DstHost,
		},
		DRKey: drkey.DRKey{Key: bytes},
	}
	return returningKey, nil
}

const insertDRKeyLvl2 = `
INSERT OR IGNORE INTO DRKeyLvl2 (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertDRKeyLvl2 inserts a second-level DRKey.
func (b *Backend) InsertDRKeyLvl2(ctx context.Context, key drkey.Lvl2Key) (int64, error) {
	res, err := b.insertDRKeyLvl2Stmt.ExecContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost,
		uint32(key.Epoch.Begin.Unix()), uint32(key.Epoch.End.Unix()), key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

const removeOutdatedDRKeyLvl2 = `
DELETE FROM DRKeyLvl2 WHERE ? >= EpochEnd
`

// RemoveOutdatedDRKeyLvl2 removes all expired second level DRKeys, I.e. those keys
// which expiration time is strictly less than the cutoff
func (b *Backend) RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := b.removeOutdatedDRKeyLvl2Stmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
