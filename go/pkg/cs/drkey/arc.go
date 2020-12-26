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

package drkey

import (
	lru "github.com/hashicorp/golang-lru"

	"github.com/scionproto/scion/go/lib/serrors"
)

var _ Lvl1PrefetchListKeeper = (*Lvl1ARC)(nil)

// Lvl1ARC maintains an Adaptative Replacement Cache, storing
// the necessary metadata to prefetch Lvl1 keys
type Lvl1ARC struct {
	cache *lru.ARCCache
}

// NewLvl1ARC returns a Lvl1ARC cache of a given size
func NewLvl1ARC(size int) (*Lvl1ARC, error) {
	cache, err := lru.NewARC(size)
	if err != nil {
		return nil, serrors.WrapStr("creating Lvl1ARC cache", err)
	}
	return &Lvl1ARC{
		cache: cache,
	}, nil
}

// Update is intended to merely update the frequency of a given remote AS
// in the ARC cache
func (c *Lvl1ARC) Update(keyPair Lvl1PrefetchInfo) {
	c.cache.Add(keyPair, keyPair)
}

// GetCachedASes returns the list of AS currently in cache
func (c *Lvl1ARC) GetLvl1InfoArray() []Lvl1PrefetchInfo {
	list := []Lvl1PrefetchInfo{}
	for _, k := range c.cache.Keys() {
		lvl1Info := k.(Lvl1PrefetchInfo)
		list = append(list, lvl1Info)
	}
	return list
}
