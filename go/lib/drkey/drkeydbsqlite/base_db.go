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
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

const (
	unableToPrepareStmt = "Unable to prepare stmt"
	unableToExecuteStmt = "Unable to execute stmt"
)

var _ drkey.BaseDB = (*dbBaseBackend)(nil)

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
