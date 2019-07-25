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

package keystore

import (
	"runtime"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
)

// Cache knows the functions to manipulate an expiring DRKey cache. Thread safe.
type Cache interface {
	Get(int64) (*drkey.DRKey, bool)
	Set(idx int64, key *drkey.DRKey)
}

// MemCache is an specifc Cache implementation.
type MemCache struct {
	cache map[int64]*drkey.DRKey
	mutex sync.Mutex

	keyDuration  time.Duration
	stopCleaning chan bool
	timeNowFcn   func() time.Time
}

// NewCache creates a new MemCache and initializes the cleaner
func NewCache(keyDuration time.Duration) *MemCache {
	c := &MemCache{
		cache:        make(map[int64]*drkey.DRKey),
		keyDuration:  keyDuration,
		stopCleaning: make(chan bool),
		timeNowFcn:   time.Now,
	}
	runtime.SetFinalizer(c, stopCleaner)
	go func() {
		defer log.LogPanicAndExit()
		c.startCleaner()
	}()
	return c
}

// Get returns the element, and an indicator of its presence
func (c *MemCache) Get(idx int64) (*drkey.DRKey, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	k, found := c.cache[idx]
	return k, found
}

// Set sets the key, and registers this element in this shard
func (c *MemCache) Set(idx int64, key *drkey.DRKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[idx] = key
}

// cleanExpired removes the current shard at once
func (c *MemCache) cleanExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := c.timeNowFcn()
	for idx, value := range c.cache {
		if !value.Epoch.Contains(now) {
			delete(c.cache, idx)
		}
	}
}

func stopCleaner(c *MemCache) {
	c.stopCleaning <- true
}

func (c *MemCache) startCleaner() {
	ticker := time.NewTicker(2 * c.keyDuration)
	for {
		select {
		case <-ticker.C:
			c.cleanExpired()
		case <-c.stopCleaning:
			ticker.Stop()
			return
		}
	}
}
