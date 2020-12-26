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
		Protocol	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		Key 		BLOB NOT NULL,
		PRIMARY KEY (SrcIsdID, SrcAsID, DstIsdID, DstAsID, EpochBegin)
	);`
)

var _ drkey.Lvl1DB = (*Lvl1Backend)(nil)

// Lvl1Backend implements a level 1 drkey DB with sqlite.
type Lvl1Backend struct {
	dbBaseBackend
}

// NewLvl1Backend creates a database and prepares all statements.
func NewLvl1Backend(path string) (*Lvl1Backend, error) {
	base, err := newBaseBackend(path, Lvl1Schema, Lvl1SchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &Lvl1Backend{
		dbBaseBackend: *base,
	}
	return b, nil
}

const getLvl1Key = `
SELECT EpochBegin, EpochEnd, Key FROM DRKeyLvl1
WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
AND Protocol=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetLvl1Key takes metadata information for the lvl1 key and a timestamp at which it should be
// valid and returns the corresponding Lvl1Key.
func (b *Lvl1Backend) GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {

	var epochBegin, epochEnd int
	var bytes []byte
	valSecs := util.TimeToSecs(meta.Validity)

	err := b.db.QueryRowContext(ctx, getLvl1Key, meta.SrcIA.ISD(), meta.SrcIA.AS(),
		meta.DstIA.ISD(), meta.DstIA.AS(), meta.ProtoId, valSecs,
		valSecs).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.Lvl1Key{}, db.NewReadError("getting lvl1 key", err)
		}
		return drkey.Lvl1Key{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.Lvl1Key{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertLvl1Key = `
INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID,
	Protocol ,EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertLvl1Key inserts a lvl1 key.
func (b *Lvl1Backend) InsertLvl1Key(ctx context.Context, key drkey.Lvl1Key) error {
	_, err := b.db.ExecContext(ctx, insertLvl1Key, key.SrcIA.ISD(), key.SrcIA.AS(), key.DstIA.ISD(),
		key.DstIA.AS(), key.ProtoId, uint32(key.Epoch.NotBefore.Unix()),
		uint32(key.Epoch.NotAfter.Unix()), key.Key[:])
	if err != nil {
		return db.NewWriteError("inserting lvl1 key", err)
	}
	return nil
}

const deleteExpiredLvl1Keys = `
DELETE FROM DRKeyLvl1 WHERE ? >= EpochEnd
`

// RemoveOutdatedLvl1Keys removes all expired lvl1 key, i.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (b *Lvl1Backend) DeleteExpiredLvl1Keys(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffSecs := util.TimeToSecs(cutoff)
	res, err := b.db.ExecContext(ctx, deleteExpiredLvl1Keys, cutoffSecs)
	if err != nil {
		return 0, db.NewWriteError("deleting outdated lvl1 key", err)
	}
	return res.RowsAffected()
}
