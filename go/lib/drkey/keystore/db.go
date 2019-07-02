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
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"

	// "github.com/scionproto/scion/go/lib/sqlite"
	// "github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

const (
	InvalidDBPath       = "Invalid path for database"
	UnableToPrepareStmt = "Unable to prepare stmt"
	UnableToExecuteStmt = "Unable to execute stmt"
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
        EpochBegin INTEGER NOT NULL,
        EpochEnd INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID, SrcHostIP, DstHostIP, EpochBegin)
	);`

	DRKeyLvl1Table = "DRKeyLvl1"
	DRKeyLvl2Table = "DRKeyLvl2"
)

const (
	getDRKeyLvl1 = `
		SELECT Key FROM DRKeyLvl1 WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
		AND EpochBegin<=? AND ?<EpochEnd
	`
	insertDRKeyLvl1 = `
		INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin, EpochEnd, Key)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl1 = `
		DELETE FROM DRKeyLvl1 WHERE ?>EpochEnd
	`
	getDRKeyLvl2 = `
		SELECT Key FROM DRKeyLvl2 WHERE Protocol=? AND Type=? AND SrcIsdID=? AND SrcAsID=? AND
		DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
		AND EpochBegin<=? AND ?<EpochEnd
	`
	insertDRKeyLvl2 = `
		INSERT OR IGNORE INTO DRKeyLvl2 (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
		SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl2 = `
		DELETE FROM DRKeyLvl2 WHERE ?>EpochEnd
	`
)

// DB is a database containing first order and second order DRKeys, stored in JSON format.
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
// GetXxxCtx methods are the context equivalents of GetXxx.
type DB struct {
	db                          *sql.DB
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

// GetLvl1Count returns the number of rows in the level 1 table
func (db *DB) GetLvl1Count() int64 {
	countRow := db.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM DRKeyLvl1;")
	var count int64
	countRow.Scan(&count)
	return count
}

// GetDRKeyLvl1 takes an pointer to a first level DRKey and a timestamp at which the DRKey should be
// valid and returns the corresponding first level DRKey.
func (db *DB) GetDRKeyLvl1(key *drkey.DRKeyLvl1, valTime uint32) (common.RawBytes, error) {
	return db.GetDRKeyLvl1Ctx(context.Background(), key, valTime)
}

// GetDRKeyLvl1Ctx is the context-aware version of GetDRKeyLvl1.
func (db *DB) GetDRKeyLvl1Ctx(ctx context.Context, key *drkey.DRKeyLvl1, valTime uint32) (common.RawBytes, error) {
	var drkeyRaw common.RawBytes
	err := db.getDRKeyLvl1Stmt.QueryRowContext(ctx, key.SrcIa.I, key.SrcIa.A, key.DstIa.I, key.DstIa.A, valTime, valTime).Scan(&drkeyRaw)
	if err != nil {
		fmt.Printf("[DEBUG] 100 breiko breiko! such much error: %v\n", err)
		return nil, common.NewBasicError(UnableToExecuteStmt, err)
	}
	return drkeyRaw, nil
}

// InsertDRKeyLvl1 inserts a first level DRKey and returns the number of affected rows.
func (db *DB) InsertDRKeyLvl1(key *drkey.DRKeyLvl1) (int64, error) {
	return db.InsertDRKeyLvl1Ctx(context.Background(), key)
}

// InsertDRKeyLvl1Ctx is the context-aware version of InsertDRKey.
func (db *DB) InsertDRKeyLvl1Ctx(ctx context.Context, key *drkey.DRKeyLvl1) (int64, error) {
	res, err := db.insertDRKeyLvl1Stmt.ExecContext(ctx, key.SrcIa.I, key.SrcIa.A, key.DstIa.I,
		key.DstIa.A, key.Epoch.Begin, key.Epoch.End, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveOutdatedDRKeyLvl1 removes all expired first level DRKeys. I.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (db *DB) RemoveOutdatedDRKeyLvl1(cutoff uint32) (int64, error) {
	return db.RemoveOutdatedDRKeyLvl1Ctx(context.Background(), cutoff)
}

// RemoveOutdatedDRKeyLvl1Ctx is the context-aware version of RemoveOutdatedDRKeyLvl1.
func (db *DB) RemoveOutdatedDRKeyLvl1Ctx(ctx context.Context, cutoff uint32) (int64, error) {
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
func (db *DB) GetDRKeyLvl2(key *drkey.DRKeyLvl2, valTime uint32) (common.RawBytes, error) {
	return db.GetDRKeyLvl2Ctx(context.Background(), key, valTime)
}

// GetDRKeyLvl2Ctx is the context-aware version of GetDRKeyLvl2.
func (db *DB) GetDRKeyLvl2Ctx(ctx context.Context, key *drkey.DRKeyLvl2, valTime uint32) (common.RawBytes, error) {
	var drkeyRaw common.RawBytes
	err := db.getDRKeyLvl2Stmt.QueryRowContext(ctx, key.Protocol, key.KeyType, key.SrcIa.I,
		key.SrcIa.A, key.DstIa.I, key.DstIa.A, key.SrcHost, key.DstHost, valTime, valTime).Scan(&drkeyRaw)
	if err != nil {
		return nil, common.NewBasicError(UnableToExecuteStmt, err)
	}
	return drkeyRaw, nil
}

// InsertDRKeyLvl2 inserts a second-level DRKey.
func (db *DB) InsertDRKeyLvl2(key *drkey.DRKeyLvl2) (int64, error) {
	return db.InsertDRKeyLvl2Ctx(context.Background(), key)
}

// InsertDRKeyLvl2Ctx is the context-aware version of InsertDRKeyLvl2.
func (db *DB) InsertDRKeyLvl2Ctx(ctx context.Context, key *drkey.DRKeyLvl2) (int64, error) {
	res, err := db.insertDRKeyLvl2Stmt.ExecContext(ctx, key.Protocol, key.KeyType, key.SrcIa.I,
		key.SrcIa.A, key.DstIa.I, key.DstIa.A, key.SrcHost, key.DstHost,
		key.Epoch.Begin, key.Epoch.End, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveOutdatedDRKeyLvl2 removes all expired second level DRKeys, I.e. those keys
// which expiration time is strictly less than the cutoff
func (db *DB) RemoveOutdatedDRKeyLvl2(cutoff uint32) (int64, error) {
	return db.RemoveOutdatedDRKeyLvl2Ctx(context.Background(), cutoff)
}

// RemoveOutdatedDRKeyLvl2Ctx is the context-aware version of RemoveOutdatedDRKeyLvl2.
func (db *DB) RemoveOutdatedDRKeyLvl2Ctx(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := db.removeOutdatedDRKeyLvl2Stmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
