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
	"runtime"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SecretValueStore keeps the current and next secret values and removes the expired ones.
type SecretValueStore struct {
	// TODO(jordiSubira): simplify class to be more consistent with keeping current and next
	// secret values.
	cache map[int64]drkey.SV
	mutex sync.Mutex

	keyDuration  time.Duration
	stopCleaning chan bool
	timeNowFcn   func() time.Time
}

// NewSecretValueStore creates a new SecretValueStore and initializes the cleaner.
func NewSecretValueStore(keyDuration time.Duration) *SecretValueStore {
	m := &SecretValueStore{
		cache:        make(map[int64]drkey.SV),
		keyDuration:  keyDuration,
		stopCleaning: make(chan bool),
		timeNowFcn:   time.Now,
	}
	runtime.SetFinalizer(m, stopCleaner)
	go func() {
		defer log.HandlePanic()
		m.startCleaner()
	}()
	return m
}

// Get returns the element, and an indicator of its presence.
func (m *SecretValueStore) Get(idx int64) (drkey.SV, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	k, found := m.cache[idx]
	return k, found
}

// Set sets the key, and registers this element in this shard.
func (m *SecretValueStore) Set(idx int64, key drkey.SV) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.cache[idx] = key
}

// cleanExpired removes the current shard at once.
func (m *SecretValueStore) cleanExpired() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := m.timeNowFcn()
	for idx, value := range m.cache {
		if !value.Epoch.Contains(now) {
			delete(m.cache, idx)
		}
	}
}

func stopCleaner(m *SecretValueStore) {
	m.stopCleaning <- true
}

func (m *SecretValueStore) startCleaner() {
	ticker := time.NewTicker(2 * m.keyDuration)
	for {
		select {
		case <-ticker.C:
			m.cleanExpired()
		case <-m.stopCleaning:
			ticker.Stop()
			return
		}
	}
}

// SecretValueFactory stores the secret value
type SecretValueFactory struct {
	keyDuration time.Duration
	masterKey   []byte
	keyMap      *SecretValueStore
	mapMutex    sync.Mutex
}

// NewSecretValueFactory return a default initialized SecretValueFactory.
func NewSecretValueFactory(masterKey []byte,
	keyDuration time.Duration) *SecretValueFactory {

	s := &SecretValueFactory{
		masterKey:   masterKey,
		keyDuration: keyDuration,
	}
	s.keyMap = NewSecretValueStore(s.keyDuration)
	return s
}

// GetSecretValue derives or reuses the secret value for this time stamp.
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
			return drkey.SV{}, serrors.WrapStr("Cannot establish the DRKey secret value", err)
		}
		s.keyMap.Set(idx, k)
	}
	return k, nil
}
