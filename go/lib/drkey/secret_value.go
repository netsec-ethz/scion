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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

const drkeySalt = "Derive DRKey Key" // same as in Python

// DRKey represents a raw binary key
type DRKey struct {
	Key common.RawBytes
}

// type DRKey common.RawBytes

func (k *DRKey) String() string {
	return fmt.Sprintf("%v", "[redacted key]")
}

// SVMeta represents the information about a DRKey secret value
type SVMeta struct {
	Epoch Epoch
}

func (k *SVMeta) String() string {
	return fmt.Sprintf("%v", k.Epoch)
}

// SV represents a DRKey secret value
type SV struct {
	SVMeta
	DRKey
}

func (k *SV) String() string {
	return fmt.Sprintf("%v %v", k.SVMeta, k.DRKey)
}

// NewSV constructs a valid SV. asSecret is typically the AS master secret
func NewSV(meta SVMeta, asSecret common.RawBytes) (SV, error) {
	msLen := len(asSecret)
	if msLen == 0 {
		return SV{}, errors.New("Invalid zero sized secret")
	}
	all := make(common.RawBytes, msLen+8)
	_, err := asSecret.WritePld(all[:msLen])
	if err != nil {
		return SV{}, err
	}
	binary.LittleEndian.PutUint32(all[msLen:], meta.Epoch.BeginAsSeconds())
	binary.LittleEndian.PutUint32(all[msLen+4:], meta.Epoch.EndAsSeconds())
	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	return SV{
		SVMeta: meta,
		DRKey:  DRKey{key},
	}, nil
}

// EpochToSV is an specifc Cache implementation.
type EpochToSV struct {
	cache map[int64]*SV
	mutex sync.Mutex

	keyDuration  time.Duration
	stopCleaning chan bool
	timeNowFcn   func() time.Time
}

// NewEpochToSV creates a new EpochToSV and initializes the cleaner
func NewEpochToSV(keyDuration time.Duration) *EpochToSV {
	m := &EpochToSV{
		cache:        make(map[int64]*SV),
		keyDuration:  keyDuration,
		stopCleaning: make(chan bool),
		timeNowFcn:   time.Now,
	}
	runtime.SetFinalizer(m, stopCleaner)
	go func() {
		defer log.LogPanicAndExit()
		m.startCleaner()
	}()
	return m
}

// Get returns the element, and an indicator of its presence
func (m *EpochToSV) Get(idx int64) (*SV, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	k, found := m.cache[idx]
	return k, found
}

// Set sets the key, and registers this element in this shard
func (m *EpochToSV) Set(idx int64, key *SV) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.cache[idx] = key
}

// cleanExpired removes the current shard at once
func (m *EpochToSV) cleanExpired() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := m.timeNowFcn()
	for idx, value := range m.cache {
		if !value.Epoch.Contains(now) {
			delete(m.cache, idx)
		}
	}
}

func stopCleaner(m *EpochToSV) {
	m.stopCleaning <- true
}

func (m *EpochToSV) startCleaner() {
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
