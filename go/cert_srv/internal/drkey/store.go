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

package drkey

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	// "github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/util"
)

// SecretValueFactory stores the secret value
type SecretValueFactory struct {
	keyDuration time.Duration
	masterKey   common.RawBytes
	keyMap      *drkey.EpochToSV
	mapMutex    sync.Mutex
}

// NewSecretValueFactory return a default initialized SecretValueFactory.
func NewSecretValueFactory(masterKey common.RawBytes,
	keyDuration time.Duration) *SecretValueFactory {

	s := &SecretValueFactory{
		masterKey:   masterKey,
		keyDuration: keyDuration,
	}
	s.keyMap = drkey.NewEpochToSV(s.keyDuration)
	return s
}

// GetKeyDuration returns the max duration of all keys.
func (s *SecretValueFactory) GetKeyDuration() time.Duration {
	return s.keyDuration
}

// SecretValue derives or reuses the secret value for this time stamp.
func (s *SecretValueFactory) GetSecretValue(t time.Time) (drkey.SV, error) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	duration := int64(s.keyDuration / time.Second) // duration in seconds
	idx := t.Unix() / duration
	k, found := s.keyMap.Get(idx)
	if !found {
		begin := uint32(idx * duration)
		end := begin + uint32(duration)
		epoch := drkey.NewEpoch(begin, end)
		var err error
		k, err = drkey.DeriveSV(drkey.SVMeta{Epoch: epoch}, s.masterKey)
		if err != nil {
			return drkey.SV{}, common.NewBasicError("Cannot establish the DRKey secret value", err)
		}
		s.keyMap.Set(idx, k)
	}
	return k, nil
}

// OldStore keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type OldStore struct {
	db drkey.DB
}

// NewOldStore creates a new beacon store backed by the configured database.
func NewOldStore(cfg config.DRKeyConfig) (*OldStore, error) {
	db, err := cfg.NewDB()
	if err != nil {
		return nil, err
	}
	s := &OldStore{
		db: db,
	}
	return s, nil
}

// GetLvl1Key returns the level 1 drkey for that meta info and valid time.
func (s *OldStore) GetLvl1Key(ctx context.Context, key drkey.Lvl1Meta,
	valTime uint32) (drkey.Lvl1Key, error) {

	return s.db.GetLvl1Key(ctx, key, valTime)
}

// InsertLvl1Key stores the key in the store.
func (s *OldStore) InsertLvl1Key(ctx context.Context, key drkey.Lvl1Key) error {
	return s.db.InsertLvl1Key(ctx, key)
}

// RemoveOutdatedLvl1Keys removes all level 1 drkeys that expire after the cutoff.
func (s *OldStore) RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedLvl1Keys(ctx, cutoff)
}

// GetLvl1SrcASes returns a slice of the source IAs appearing in the level 1 key entries.
func (s *OldStore) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	return s.db.GetLvl1SrcASes(ctx)
}

// GetValidLvl1SrcASes returns a slice of the source IAs appearing in all level 1 key entries that
// are not expired at the given time point.
func (s *OldStore) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	return s.db.GetValidLvl1SrcASes(ctx, valTime)
}

// GetLvl2Key returns the level 2 drkey for that meta info and valid time.
func (s *OldStore) GetLvl2Key(ctx context.Context, key drkey.Lvl2Meta,
	valTime uint32) (drkey.Lvl2Key, error) {

	return s.db.GetLvl2Key(ctx, key, valTime)
}

// InsertLvl2Key stores the key in the store.
func (s *OldStore) InsertLvl2Key(ctx context.Context, key drkey.Lvl2Key) error {
	return s.db.InsertLvl2Key(ctx, key)
}

// RemoveOutdatedLvl2Keys removes all level 2 drkeys that expire after the cutoff.
func (s *OldStore) RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedLvl2Keys(ctx, cutoff)
}

// ----------------------------------------------------------------------------------------------------------- intentionally long, remove

// Store keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type Store struct {
	ia addr.IA
	db drkey.DB
	// msger infra.Messenger
}

// NewStore constructs a DRKey Store.
func NewStore(db drkey.DB, local addr.IA) *Store {
	s := &Store{
		db: db,
		ia: local,
	}
	return s
}

// func (s *Store) SetMessenger(msger infra.Messenger) {
// 	if s.msger != nil {
// 		panic("messenger already set")
// 	}
// 	s.msger = msger
// }

func (s *Store) GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta,
	valTime time.Time) (drkey.Lvl1Key, error) {

	if meta.SrcIA == s.ia {
		return drkey.Lvl1Key{}, common.NewBasicError("Logic error: cannot query the store for a "+
			"level 1 key when the local AS is the source of the key", nil)
	}
	// look in the DB
	k, err := s.db.GetLvl1Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl1Key{}, common.NewBasicError("Problem retrieving key from DB", err)
	}
	// get it from another server
	return k, nil
}
