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

type Store struct {
	sv secretValueSimpleStore
	db DB
}

// NewDRKeyStore constructs a DRKey Store
func NewStore(db DB) *Store {
	s := &Store{
		sv: secretValueSimpleStore{},
		db: db,
	}
	s.sv.initDefaultValues()
	return s
}

func (s *Store) GetKeyDuration() time.Duration {
	return s.sv.keyDuration
}

func (s *Store) SetKeyDuration(duration time.Duration) error {
	s.sv.keyDuration = duration
	return nil
}

func (s *Store) GetMasterKey() common.RawBytes {
	return s.sv.masterKey
}

func (s *Store) SetMasterKey(key common.RawBytes) error {
	// test this master key now
	_, err := NewSV(SVMeta{}, key)
	if err != nil {
		return common.NewBasicError("Cannot use this master key as the secret for DRKey", err)
	}
	s.sv.masterKey = key
	return nil
}

// SecretValue derives or reuses the secret value for this time stamp
func (s *Store) SecretValue(t time.Time) (*SV, error) {
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
			return nil, common.NewBasicError("Cannot establish the DRKey secret value", err)
		}
		k = &key
		s.sv.keyMap.Set(idx, k)
	}
	return k, nil
}

func (s *Store) GetDRKeyLvl1(ctx context.Context, key Lvl1Meta, valTime uint32) (Lvl1Key, error) {
	return s.db.GetDRKeyLvl1(ctx, key, valTime)
}

func (s *Store) InsertDRKeyLvl1(ctx context.Context, key Lvl1Key) (int64, error) {
	return s.db.InsertDRKeyLvl1(ctx, key)
}

func (s *Store) RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedDRKeyLvl1(ctx, cutoff)
}

func (s *Store) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	return s.db.GetLvl1SrcASes(ctx)
}

func (s *Store) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	return s.db.GetValidLvl1SrcASes(ctx, valTime)
}

func (s *Store) GetDRKeyLvl2(ctx context.Context, key Lvl2Meta, valTime uint32) (Lvl2Key, error) {
	return s.db.GetDRKeyLvl2(ctx, key, valTime)
}

func (s *Store) InsertDRKeyLvl2(ctx context.Context, key Lvl2Key) (int64, error) {
	return s.db.InsertDRKeyLvl2(ctx, key)
}

func (s *Store) RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error) {
	return s.db.RemoveOutdatedDRKeyLvl2(ctx, cutoff)
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
