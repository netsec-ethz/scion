// Copyright 2021 ETH Zurich
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
	SVSchemaVersion = 1
	SVSchema        = `
	CREATE TABLE DRKeySV (
		Protocol	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		Key 		BLOB NOT NULL,
		PRIMARY KEY (Protocol, EpochBegin)
	);`
)

var _ drkey.SecretValueDB = (*SVBackend)(nil)

// SVBackend implements a SV DB with sqlite.
type SVBackend struct {
	dbBaseBackend
}

// NewSVBackend creates a database and prepares all statements.
func NewSVBackend(path string) (*SVBackend, error) {
	base, err := newBaseBackend(path, SVSchema, SVSchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &SVBackend{
		dbBaseBackend: *base,
	}
	return b, nil
}

const getSV = `
SELECT EpochBegin, EpochEnd, Key FROM DRKeySV
WHERE Protocol=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetSV takes the protocol and the time at which the SV must be
// valid and return such a SV.
func (b *SVBackend) GetSV(ctx context.Context, meta drkey.SVMeta) (drkey.SV, error) {

	var epochBegin, epochEnd int
	var bytes []byte
	valSecs := util.TimeToSecs(meta.Validity)
	err := b.db.QueryRowContext(ctx, getSV, meta.ProtoId, valSecs, valSecs).Scan(&epochBegin,
		&epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.SV{}, db.NewReadError("getting SV", err)
		}
		return drkey.SV{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.SV{
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		ProtoId: meta.ProtoId,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertSV = `
INSERT OR IGNORE INTO DRKeySV (Protocol,EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?)
`

// InsertSV inserts a SV.
func (b *SVBackend) InsertSV(ctx context.Context, key drkey.SV) error {
	_, err := b.db.ExecContext(ctx, insertSV, key.ProtoId, uint32(key.Epoch.NotBefore.Unix()),
		uint32(key.Epoch.NotAfter.Unix()), key.Key[:])
	if err != nil {
		return db.NewWriteError("inserting SV", err)
	}
	return nil
}

const deleteExpiredSV = `
DELETE FROM DRKeySV WHERE ? >= EpochEnd
`

// RemoveOutdatedSV removes all expired SVs, i.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (b *SVBackend) DeleteExpiredSV(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffSecs := util.TimeToSecs(cutoff)
	res, err := b.db.ExecContext(ctx, deleteExpiredSV, cutoffSecs)
	if err != nil {
		return 0, db.NewWriteError("deleting outdated SVs", err)
	}
	return res.RowsAffected()
}
