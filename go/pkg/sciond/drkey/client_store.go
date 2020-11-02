// Copyright 2020 ETH Zurich
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

package drkey

import (
	"context"
	"database/sql"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Drkey fetching errors.
var (
	ErrDB        = serrors.New("error with DB")
	ErrInsertDB  = serrors.New("error inserting in DB")
	ErrMessenger = serrors.New("error with Messenger")
)

// Fetcher obtains a Lvl2 DRKey from the local CS.
type Fetcher interface {
	GetDRKeyLvl2(ctx context.Context, meta drkey.Lvl2Meta, a addr.IA,
		valTime time.Time) (drkey.Lvl2Key, error)
}

// ClientStore is the DRKey store used in the client side, i.e. sciond.
// It implements drkeystorage.ClientStore.
type ClientStore struct {
	ia      addr.IA
	db      drkey.Lvl2DB
	fetcher Fetcher
}

var _ drkeystorage.ClientStore = &ClientStore{}

// NewClientStore constructs a new client store without assigned messenger.
func NewClientStore(local addr.IA, db drkey.Lvl2DB, fetcher Fetcher) *ClientStore {
	return &ClientStore{
		ia:      local,
		db:      db,
		fetcher: fetcher,
	}
}

// GetLvl2Key returns the level 2 drkey from the local DB or if not found, by asking our local CS.
func (s *ClientStore) GetLvl2Key(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (drkey.Lvl2Key, error) {

	logger := log.FromCtx(ctx)
	// is it in storage?
	k, err := s.db.GetLvl2Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl2Key{}, serrors.Wrap(ErrDB, err)
	}
	logger.Debug("[DRKey ClientStore] Level 2 key not stored. Requesting it to CS")
	// if not, ask our CS for it

	k, err = s.fetcher.GetDRKeyLvl2(ctx, meta, s.ia, valTime)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.Wrap(ErrMessenger, err)
	}
	if err = s.db.InsertLvl2Key(ctx, k); err != nil {
		logger.Error("[DRKey ClientStore] Could not insert level 2 in DB", "error", err)
		return k, serrors.Wrap(ErrInsertDB, err)
	}
	return k, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientStore) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now()))
	return int(i), err
}
