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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
)

const (
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

var _ drkey.Lvl2DB = (*Lvl2Backend)(nil)

// Lvl2Backend implements a level 2 drkey DB with sqlite.
type Lvl2Backend struct {
	dbBaseBackend
	getLvl2KeyStmt             *sql.Stmt
	insertLvl2KeyStmt          *sql.Stmt
	removeOutdatedLvl2KeysStmt *sql.Stmt
}

// NewLvl2Backend creates a database and prepares all statements.
func NewLvl2Backend(path string) (*Lvl2Backend, error) {
	base, err := newBaseBackend(path, Lvl2Schema, Lvl2SchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &Lvl2Backend{
		dbBaseBackend: *base,
	}
	stmts := preparedStmts{
		getLvl2Key:             &b.getLvl2KeyStmt,
		insertLvl2Key:          &b.insertLvl2KeyStmt,
		removeOutdatedLvl2Keys: &b.removeOutdatedLvl2KeysStmt,
	}
	if err := base.prepareAll(stmts); err != nil {
		return nil, err
	}
	return b, nil
}

const getLvl2Key = `
SELECT EpochBegin, EpochEnd, Key
FROM DRKeyLvl2 WHERE Protocol=? AND Type=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetLvl2Key takes a source, destination and additional ISD-AS, a source, destination and
// additional host, and a timestamp at which the DRKey should be valid and
// returns a second level DRKey of the request type
func (b *Lvl2Backend) GetLvl2Key(ctx context.Context, key drkey.Lvl2Meta, valTime uint32) (drkey.Lvl2Key, error) {
	var epochBegin int
	var epochEnd int
	var bytes []byte

	err := b.getLvl2KeyStmt.QueryRowContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost, valTime,
		valTime).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			err = common.NewBasicError(unableToExecuteStmt, err)
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
		Key: drkey.DRKey(bytes),
	}
	return returningKey, nil
}

const insertLvl2Key = `
INSERT OR IGNORE INTO DRKeyLvl2 (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertLvl2Key inserts a second-level DRKey.
func (b *Lvl2Backend) InsertLvl2Key(ctx context.Context, key drkey.Lvl2Key) error {
	_, err := b.insertLvl2KeyStmt.ExecContext(ctx, key.Protocol, key.KeyType, key.SrcIA.I,
		key.SrcIA.A, key.DstIA.I, key.DstIA.A, key.SrcHost, key.DstHost,
		uint32(key.Epoch.NotBefore.Time.Unix()), uint32(key.Epoch.NotAfter.Time.Unix()), key.Key)
	if err != nil {
		return err
	}
	return nil
}

const removeOutdatedLvl2Keys = `
DELETE FROM DRKeyLvl2 WHERE ? >= EpochEnd
`

// RemoveOutdatedLvl2Keys removes all expired second level DRKeys, I.e. those keys
// which expiration time is strictly less than the cutoff
func (b *Lvl2Backend) RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error) {
	res, err := b.removeOutdatedLvl2KeysStmt.ExecContext(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
