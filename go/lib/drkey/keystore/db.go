// Copyright 2018 ETH Zurich
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

package keystore

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
	InvalidDBPath       = "Invalid path for database"
	UnableToPrepareStmt = "Unable to prepare stmt"
	UnableToExecuteStmt = "Unable to execute stmt"
)

var (
	ErrNoKeys = sql.ErrNoRows
)

const (
	Path          = "drkeyDB.sqlite3"
	SchemaVersion = 1
	Schema        = `
	CREATE TABLE DRKeyLvl1 (
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin)
	);

	CREATE TABLE DRKeyLvl2 (
		Protocol	TEXT NOT NULL,
		Type		INTEGER NOT NULL,
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		SrcHostIP 	TEXT,
        DstHostIP	TEXT,
        EpochBegin  INTEGER NOT NULL,
        EpochEnd    INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID, SrcHostIP, DstHostIP, EpochBegin)
	);`

	DRKeyLvl1Table = "DRKeyLvl1"
	DRKeyLvl2Table = "DRKeyLvl2"
)

const (
	GetL1SrcASes = `
		SELECT SrcIsdID as I, SrcASID as A FROM DRKeyLvl1
		GROUP BY I, A
	`
	GetValidL1SrcASes = `
		SELECT SrcIsdID as I, SrcASID as A FROM DRKeyLvl1
		WHERE EpochBegin <= ? AND ? < EpochEnd
		GROUP BY I, A
	`
	getDRKeyLvl1 = `
		SELECT EpochBegin, EpochEnd, Key FROM DRKeyLvl1
		WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
		AND EpochBegin<=? AND ?<EpochEnd
	`
	insertDRKeyLvl1 = `
		INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin, EpochEnd, Key)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl1 = `
		DELETE FROM DRKeyLvl1 WHERE ? >= EpochEnd
	`
	getDRKeyLvl2 = `
		SELECT EpochBegin, EpochEnd, Key
		FROM DRKeyLvl2 WHERE Protocol=? AND Type=? AND SrcIsdID=? AND SrcAsID=? AND
		DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
		AND EpochBegin<=? AND ?<EpochEnd
	`
	insertDRKeyLvl2 = `
		INSERT OR IGNORE INTO DRKeyLvl2 (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
		SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl2 = `
		DELETE FROM DRKeyLvl2 WHERE ? >= EpochEnd
	`
)

// DRKeyStore has all the functions dealing with storage/retrieval of DRKeys level 1 and 2
type DRKeyStore interface {
	Close() error
	// Level 1 specific functions
	GetDRKeyLvl1(ctx context.Context, key *drkey.DRKeyLvl1, valTime uint32) (*drkey.DRKeyLvl1, error)
	InsertDRKeyLvl1(ctx context.Context, key *drkey.DRKeyLvl1) (int64, error)
	RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error)
	// GetL1SrcASes returns a list of distinct ASes seen in the SRC of a L1 key
	GetL1SrcASes(ctx context.Context) ([]addr.IA, error)
	// GetValidL1SrcASes returns a list of distinct IAs that have a still valid L1 key
	GetValidL1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error)
	// Level 2 specific
	GetDRKeyLvl2(ctx context.Context, key *drkey.DRKeyLvl2, valTime uint32) (*drkey.DRKeyLvl2, error)
	InsertDRKeyLvl2(ctx context.Context, key *drkey.DRKeyLvl2) (int64, error)
	RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error)
}

// DB is a database containing first order and second order DRKeys, stored in JSON format.
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
// GetXxxCtx methods are the context equivalents of GetXxx.
type DB struct {
	db                          *sql.DB
	GetL1SrcASesStmt            *sql.Stmt
	GetValidL1SrcASesStmt       *sql.Stmt
	getDRKeyLvl1Stmt            *sql.Stmt
	insertDRKeyLvl1Stmt         *sql.Stmt
	removeOutdatedDRKeyLvl1Stmt *sql.Stmt
	getDRKeyLvl2Stmt            *sql.Stmt
	insertDRKeyLvl2Stmt         *sql.Stmt
	removeOutdatedDRKeyLvl2Stmt *sql.Stmt
}

// New creates a database and prepares all prepares all statements.
func New(path string) (*DB, error) {
	if len(path) <= 0 {
		return nil, common.NewBasicError(InvalidDBPath, nil)
	}
	var err error
	keystore := &DB{}
	if keystore.db, err = db.NewSqlite(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			keystore.db.Close()
		}
	}()
	if keystore.GetL1SrcASesStmt, err = keystore.db.Prepare(GetL1SrcASes); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.GetValidL1SrcASesStmt, err = keystore.db.Prepare(GetValidL1SrcASes); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.getDRKeyLvl1Stmt, err = keystore.db.Prepare(getDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.insertDRKeyLvl1Stmt, err = keystore.db.Prepare(insertDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.removeOutdatedDRKeyLvl1Stmt, err = keystore.db.Prepare(removeOutdatedDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.getDRKeyLvl2Stmt, err = keystore.db.Prepare(getDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.insertDRKeyLvl2Stmt, err = keystore.db.Prepare(insertDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if keystore.removeOutdatedDRKeyLvl2Stmt, err = keystore.db.Prepare(removeOutdatedDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	return keystore, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

// GetL1SrcASes returns a list of all distinct src IAs seen in the L1 table
func (db *DB) GetL1SrcASes(ctx context.Context) ([]addr.IA, error) {
	rows, err := db.GetL1SrcASesStmt.QueryContext(ctx)
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

// GetValidL1SrcASes returns a list of distinct src IAs seen in the L1 table
// If the L1 key is still valid according to valTime, its src IA will be in the list
func (db *DB) GetValidL1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	rows, err := db.GetValidL1SrcASesStmt.QueryContext(ctx, valTime, valTime)
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
func (db *DB) GetLvl1Count() int64 {
	countRow := db.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM DRKeyLvl1;")
	var count int64
	countRow.Scan(&count)
	return count
}

// GetDRKeyLvl1 takes an pointer to a first level DRKey and a timestamp at which the DRKey should be
// valid and returns the corresponding first level DRKey.
func (db *DB) GetDRKeyLvl1(ctx context.Context, key *drkey.DRKeyLvl1, valTime uint32) (*drkey.DRKeyLvl1, error) {
	var epochBegin, epochEnd int
	var bytes common.RawBytes
	err := db.getDRKeyLvl1Stmt.QueryRowContext(ctx, key.SrcIA.I, key.SrcIA.A,
		key.DstIA.I, key.DstIA.A, valTime, valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return nil, err
	}
	returningKey := &drkey.DRKeyLvl1{
		DRKey: drkey.DRKey{
			Epoch: drkey.Epoch{
				Begin: uint32(epochBegin),
				End:   uint32(epochEnd),
			},
			Key: bytes,
		},
		SrcIA: key.SrcIA,
		DstIA: key.DstIA,
	}
	return returningKey, nil
}

// InsertDRKeyLvl1 inserts a first level DRKey and returns the number of affected rows.
func (db *DB) InsertDRKeyLvl1(ctx context.Context, key *drkey.DRKeyLvl1) (int64, error) {
	res, err := db.insertDRKeyLvl1Stmt.ExecContext(ctx, key.SrcIA.I, key.SrcIA.A, key.DstIA.I,
		key.DstIA.A, key.Epoch.Begin, key.Epoch.End, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveOutdatedDRKeyLvl1 removes all expired first level DRKeys. I.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (db *DB) RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := db.removeOutdatedDRKeyLvl1Stmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetLvl2Count returns the number of rows in the level 1 table
func (db *DB) GetLvl2Count() int64 {
	countRow := db.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM DRKeyLvl2;")
	var count int64
	countRow.Scan(&count)
	return count
}

// GetDRKeyLvl2 takes a source, destination and additional ISD-AS, a source, destination and
// additional host, and a timestamp at which the DRKey should be valid and
// returns a second level DRKey of the request type
func (db *DB) GetDRKeyLvl2(ctx context.Context, key *drkey.DRKeyLvl2, valTime uint32) (*drkey.DRKeyLvl2, error) {
	var epochBegin int
	var epochEnd int
	var bytes common.RawBytes

	err := db.getDRKeyLvl2Stmt.QueryRowContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost, valTime,
		valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(UnableToExecuteStmt, err)
		}
		return nil, err
	}
	returningKey := &drkey.DRKeyLvl2{
		DRKeyLvl1: drkey.DRKeyLvl1{
			DRKey: drkey.DRKey{
				Epoch: drkey.Epoch{
					Begin: uint32(epochBegin),
					End:   uint32(epochEnd),
				},
				Key: bytes,
			},
			SrcIA: key.SrcIA,
			DstIA: key.DstIA,
		},
		KeyType:  key.KeyType,
		Protocol: key.Protocol,
		SrcHost:  key.SrcHost,
		DstHost:  key.DstHost,
	}
	return returningKey, nil
}

// InsertDRKeyLvl2 inserts a second-level DRKey.
func (db *DB) InsertDRKeyLvl2(ctx context.Context, key *drkey.DRKeyLvl2) (int64, error) {
	res, err := db.insertDRKeyLvl2Stmt.ExecContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost,
		key.Epoch.Begin, key.Epoch.End, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveOutdatedDRKeyLvl2 removes all expired second level DRKeys, I.e. those keys
// which expiration time is strictly less than the cutoff
func (db *DB) RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := db.removeOutdatedDRKeyLvl2Stmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
