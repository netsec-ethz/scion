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
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

const (
	unableToPrepareStmt = "Unable to prepare stmt"
	unableToExecuteStmt = "Unable to execute stmt"
)

const (
	// Lvl1SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	Lvl1SchemaVersion = 1
	// Lvl1Schema is the SQLite database layout.
	Lvl1Schema = `
	CREATE TABLE DRKeyLvl1 (
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin)
	);`

	// Lvl2SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	Lvl2SchemaVersion = 1
	// Lvl2Schema is the SQLite database layout.
	Lvl2Schema = `
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
)

// dbBaseBackend is the common part of all level backends.
type dbBaseBackend struct {
	db *sql.DB
}

// newBaseBackend builds the base backend common for all level backends.
func newBaseBackend(path, schema string, version int) (*dbBaseBackend, error) {
	db, err := db.NewSqlite(path, schema, version)
	if err != nil {
		return nil, err
	}
	return &dbBaseBackend{
		db: db,
	}, nil
}

type preparedStmts map[string]**sql.Stmt

// prepareAll will create the prepared statements or return an error as soon as one fails.
func (b *dbBaseBackend) prepareAll(stmts preparedStmts) error {
	var err error
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			b.Close()
		}
	}()
	for str, stmt := range stmts {
		if *stmt, err = b.db.Prepare(str); err != nil {
			return common.NewBasicError(unableToPrepareStmt, err)
		}
	}
	return nil
}

// Close closes the database connection.
func (b *dbBaseBackend) Close() error {
	return b.db.Close()
}

// SetMaxOpenConns sets the maximum number of open connections.
func (b *dbBaseBackend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (b *dbBaseBackend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}
