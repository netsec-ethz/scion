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
	unableToPrepareStmt = "Unable to prepare stmt"
	unableToExecuteStmt = "Unable to execute stmt"
)

var _ drkey.Lvl1DB = (*Lvl1Backend)(nil)

// Lvl1Backend implements a level 1 drkey DB with sqlite.
type Lvl1Backend struct {
	db                         *sql.DB
	getLvl1SrcASesStmt         *sql.Stmt
	getValidLvl1SrcASesStmt    *sql.Stmt
	getLvl1KeyStmt             *sql.Stmt
	insertLvl1KeyStmt          *sql.Stmt
	removeOutdatedLvl1KeysStmt *sql.Stmt
}

// NewLvl1Backend creates a database and prepares all statements.
func NewLvl1Backend(path string) (*Lvl1Backend, error) {
	db, err := db.NewSqlite(path, Lvl1Schema, Lvl1SchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &Lvl1Backend{
		db: db,
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			b.db.Close()
		}
	}()
	if b.getLvl1SrcASesStmt, err = b.db.Prepare(getLvl1SrcASes); err != nil {
		return nil, common.NewBasicError(unableToPrepareStmt, err)
	}
	if b.getValidLvl1SrcASesStmt, err = b.db.Prepare(getValidLvl1SrcASes); err != nil {
		return nil, common.NewBasicError(unableToPrepareStmt, err)
	}
	if b.getLvl1KeyStmt, err = b.db.Prepare(getLvl1Key); err != nil {
		return nil, common.NewBasicError(unableToPrepareStmt, err)
	}
	if b.insertLvl1KeyStmt, err = b.db.Prepare(insertLvl1Key); err != nil {
		return nil, common.NewBasicError(unableToPrepareStmt, err)
	}
	if b.removeOutdatedLvl1KeysStmt, err = b.db.Prepare(removeOutdatedLvl1Keys); err != nil {
		return nil, common.NewBasicError(unableToPrepareStmt, err)
	}
	return b, nil
}

// Close closes the database connection.
func (b *Lvl1Backend) Close() error {
	return b.db.Close()
}

// SetMaxOpenConns sets the maximum number of open connections.
func (b *Lvl1Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (b *Lvl1Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

const getLvl1SrcASes = `
SELECT SrcIsdID as I, SrcASID as A FROM DRKeyLvl1
GROUP BY I, A
`

// GetLvl1SrcASes returns a list of distinct ASes seen in the SRC of a level 1 key
func (b *Lvl1Backend) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	rows, err := b.getLvl1SrcASesStmt.QueryContext(ctx)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(unableToExecuteStmt, err)
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
func (b *Lvl1Backend) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	rows, err := b.getValidLvl1SrcASesStmt.QueryContext(ctx, valTime, valTime)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(unableToExecuteStmt, err)
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

const getLvl1Key = `
SELECT EpochBegin, EpochEnd, Key FROM DRKeyLvl1
WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetLvl1Key takes an pointer to a first level DRKey and a timestamp at which the DRKey should be
// valid and returns the corresponding first level DRKey.
func (b *Lvl1Backend) GetLvl1Key(ctx context.Context, key drkey.Lvl1Meta, valTime uint32) (drkey.Lvl1Key, error) {
	var epochBegin, epochEnd int
	var bytes common.RawBytes
	err := b.getLvl1KeyStmt.QueryRowContext(ctx, key.SrcIA.I, key.SrcIA.A,
		key.DstIA.I, key.DstIA.A, valTime, valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(unableToExecuteStmt, err)
		}
		return drkey.Lvl1Key{}, err
	}
	returningKey := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
			SrcIA: key.SrcIA,
			DstIA: key.DstIA,
		},
		Key: drkey.DRKey(bytes),
	}
	return returningKey, nil
}

const insertLvl1Key = `
INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?)
`

// InsertLvl1Key inserts a first level DRKey and returns the number of affected rows.
func (b *Lvl1Backend) InsertLvl1Key(ctx context.Context, key drkey.Lvl1Key) error {
	_, err := b.insertLvl1KeyStmt.ExecContext(ctx, key.SrcIA.I, key.SrcIA.A, key.DstIA.I,
		key.DstIA.A, uint32(key.Epoch.Begin.Unix()), uint32(key.Epoch.End.Unix()), key.Key)
	if err != nil {
		return err
	}
	return nil
}

const removeOutdatedLvl1Keys = `
DELETE FROM DRKeyLvl1 WHERE ? >= EpochEnd
`

// RemoveOutdatedLvl1Keys removes all expired first level DRKeys. I.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (b *Lvl1Backend) RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := b.removeOutdatedLvl1KeysStmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
