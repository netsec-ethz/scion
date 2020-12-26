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

package sqlite

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// Lvl2SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	Lvl2SchemaVersion = 1
	// Lvl2Schema is the SQLite database layout.
	Lvl2Schema = `
	CREATE TABLE ASHost (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		DstHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, DstHostIP, EpochBegin)
	);

	CREATE TABLE HostAS (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		SrcHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, SrcHostIP, EpochBegin)
	);

	CREATE TABLE HostHost (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		SrcHostIP	TEXT,
		DstHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, SrcHostIP, DstHostIP, EpochBegin)
	);
	`
)

var _ drkey.Lvl2DB = (*Lvl2Backend)(nil)

// Lvl2Backend implements a level 2 drkey DB with sqlite.
type Lvl2Backend struct {
	dbBaseBackend
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
	return b, nil
}

const getASHostKey = `
SELECT EpochBegin, EpochEnd, Key
FROM ASHost WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetASHostKey takes metadata information for the ASHost key and a timestamp
// at which it should be valid and returns the corresponding key.
func (b *Lvl2Backend) GetASHostKey(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := b.db.QueryRowContext(ctx, getASHostKey, meta.ProtoId, meta.SrcIA.ISD(), meta.SrcIA.AS(), meta.DstIA.ISD(), meta.DstIA.AS(), meta.DstHost, valSecs,
		valSecs).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.ASHostKey{}, db.NewReadError("getting ASHost key", err)
		}
		return drkey.ASHostKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		DstHost: meta.DstHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertASHostKey = `
INSERT OR IGNORE INTO ASHost (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertASHostKey inserts a ASHost key.
func (b *Lvl2Backend) InsertASHostKey(ctx context.Context, key drkey.ASHostKey) error {

	_, err := b.db.ExecContext(ctx, insertASHostKey, key.ProtoId, key.SrcIA.ISD(), key.SrcIA.AS(), key.DstIA.ISD(), key.DstIA.AS(), key.DstHost,
		uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()), key.Key[:])
	if err != nil {
		return db.NewWriteError("inserting ASHost key", err)
	}
	return nil
}

const getHostASKey = `
SELECT EpochBegin, EpochEnd, Key
FROM HostAS WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetHostASKey takes metadata information for the HostAS key and a timestamp
// at which it should be valid and returns the corresponding key.
func (b *Lvl2Backend) GetHostASKey(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := b.db.QueryRowContext(ctx, getHostASKey, meta.ProtoId, meta.SrcIA.ISD(), meta.SrcIA.AS(), meta.DstIA.ISD(), meta.DstIA.AS(), meta.SrcHost, valSecs,
		valSecs).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.HostASKey{}, db.NewReadError("getting Host-AS key", err)
		}
		return drkey.HostASKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertHostASKey = `
INSERT OR IGNORE INTO HostAS (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertHostASKey inserts a HostAS key.
func (b *Lvl2Backend) InsertHostASKey(ctx context.Context, key drkey.HostASKey) error {
	_, err := b.db.ExecContext(ctx, insertHostASKey, key.ProtoId, key.SrcIA.ISD(), key.SrcIA.AS(), key.DstIA.ISD(), key.DstIA.AS(), key.SrcHost,
		uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()), key.Key[:])
	if err != nil {
		return db.NewWriteError("inserting Host-As key", err)
	}
	return nil
}

const getHostHostKey = `
SELECT EpochBegin, EpochEnd, Key
FROM HostHost WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetHostHostKey takes metadata information for the HostHost key and a timestamp
// at which it should be valid and returns the corresponding key.
func (b *Lvl2Backend) GetHostHostKey(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := b.db.QueryRowContext(ctx, getHostHostKey, meta.ProtoId, meta.SrcIA.ISD(), meta.SrcIA.AS(), meta.DstIA.ISD(), meta.DstIA.AS(), meta.SrcHost, meta.DstHost, valSecs,
		valSecs).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.HostHostKey{}, db.NewReadError("getting Host-Host key", err)
		}
		return drkey.HostHostKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertHostHostKey = `
INSERT OR IGNORE INTO HostHost (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertHostHostKey inserts a HostHost key.
func (b *Lvl2Backend) InsertHostHostKey(ctx context.Context, key drkey.HostHostKey) error {
	_, err := b.db.ExecContext(ctx, insertHostHostKey, key.ProtoId, key.SrcIA.ISD(), key.SrcIA.AS(), key.DstIA.ISD(), key.DstIA.AS(), key.SrcHost, key.DstHost,
		uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()), key.Key[:])
	if err != nil {
		return db.NewWriteError("inserting Host-Host key", err)
	}
	return nil
}

const deleteExpiredLvl2Keys = `
DELETE FROM ASHost WHERE ? >= EpochEnd;
DELETE FROM HostAS WHERE ? >= EpochEnd;
DELETE FROM HostHost WHERE ? >= EpochEnd;
`

// RemoveOutdatedLvl2Keys removes all expired lvl2/3 keys, i.e. those keys
// which expiration time is strictly less than the cutoff
func (b *Lvl2Backend) DeleteExpiredLvl2Keys(ctx context.Context, cutoff time.Time) (int64, error) {
	// XXX(JordiSubira): It only returns the removed rows for the last statement.
	// We might want to change this return value.
	cutoffSecs := util.TimeToSecs(cutoff)
	res, err := b.db.ExecContext(ctx, deleteExpiredLvl2Keys, cutoffSecs, cutoffSecs, cutoffSecs)
	if err != nil {
		return 0, db.NewWriteError("deleting outdated lvl2 key", err)
	}
	return res.RowsAffected()
}
