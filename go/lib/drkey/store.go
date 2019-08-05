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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Store keeps track of the drkey entries at different levels, from SV to level 2. It is backed
// by a drkey.DB .
type Store struct {
	sv secretValueSimpleStore
	db DB
}

// NewStore constructs a DRKey Store.
func NewStore(db DB) *Store {
	s := &Store{
		sv: secretValueSimpleStore{},
		db: db,
	}
	s.sv.initDefaultValues()
	return s
}

// GetKeyDuration returns the max duration of all keys.
func (s *Store) GetKeyDuration() time.Duration {
	return s.sv.keyDuration
}

// SetKeyDuration sets the duration of all keys. The duration will not be in effect until this and
// next epochs expire.
func (s *Store) SetKeyDuration(duration time.Duration) error {
	// TODO(juagargi): enforce keeping the duration for this and next epochs.
	s.sv.keyDuration = duration
	return nil
}

// GetMasterKey returns a copy of the master key from the store.
func (s *Store) GetMasterKey() common.RawBytes {
	return s.sv.masterKey
}

// SetMasterKey copies the master key to this store. It is used to derive the secret value.
func (s *Store) SetMasterKey(key common.RawBytes) error {
	// test this master key now
	_, err := NewSV(SVMeta{}, key)
	if err != nil {
		return common.NewBasicError("Cannot use this master key as the secret for DRKey", err)
	}
	s.sv.masterKey = key
	// TODO(juagargi): invalidate (remove) existing secret values ?
	return nil
}

// SecretValue derives or reuses the secret value for this time stamp.
func (s *Store) SecretValue(t time.Time) (SV, error) {
	s.sv.mapMutex.Lock()
	defer s.sv.mapMutex.Unlock()

	duration := int64(s.sv.keyDuration / time.Second) // duration in seconds
	idx := t.Unix() / duration
	k, found := s.sv.keyMap.Get(idx)
	if !found {
		begin := uint32(idx * duration)
		end := begin + uint32(duration)
		epoch := NewEpoch(begin, end)
		key, err := NewSV(SVMeta{Epoch: epoch}, s.sv.masterKey)
		if err != nil {
			return SV{}, common.NewBasicError("Cannot establish the DRKey secret value", err)
		}
		k = &key
		s.sv.keyMap.Set(idx, k)
	}
	return *k, nil
}

// GetLvl1Key returns the level 1 drkey for that meta info and valid time.
func (s *Store) GetLvl1Key(ctx context.Context, key Lvl1Meta, valTime uint32) (Lvl1Key, error) {
	return s.db.GetLvl1Key(ctx, key, valTime)
}

// InsertLvl1Key stores the key in the store.
func (s *Store) InsertLvl1Key(ctx context.Context, key Lvl1Key) error {
	return s.db.InsertLvl1Key(ctx, key)
}

// RemoveOutdatedLvl1Keys removes all level 1 drkeys that expire after the cutoff.
func (s *Store) RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedLvl1Keys(ctx, cutoff)
}

// GetLvl1SrcASes returns a slice of the source IAs appearing in the level 1 key entries.
func (s *Store) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	return s.db.GetLvl1SrcASes(ctx)
}

// GetValidLvl1SrcASes returns a slice of the source IAs appearing in all level 1 key entries that
// are not expired at the given time point.
func (s *Store) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	return s.db.GetValidLvl1SrcASes(ctx, valTime)
}

// GetLvl2Key returns the level 2 drkey for that meta info and valid time.
func (s *Store) GetLvl2Key(ctx context.Context, key Lvl2Meta, valTime uint32) (Lvl2Key, error) {
	return s.db.GetLvl2Key(ctx, key, valTime)
}

// InsertLvl2Key stores the key in the store.
func (s *Store) InsertLvl2Key(ctx context.Context, key Lvl2Key) error {
	return s.db.InsertLvl2Key(ctx, key)
}

// RemoveOutdatedLvl2Keys removes all level 2 drkeys that expire after the cutoff.
func (s *Store) RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedLvl2Keys(ctx, cutoff)
}

// secretValueSimpleStore stores the secret value
type secretValueSimpleStore struct {
	keyDuration time.Duration
	masterKey   common.RawBytes
	keyMap      *EpochToSV
	mapMutex    sync.Mutex
}

func (s *secretValueSimpleStore) initDefaultValues() {
	s.keyDuration = 24 * time.Hour
	s.keyMap = NewEpochToSV(s.keyDuration)
}
