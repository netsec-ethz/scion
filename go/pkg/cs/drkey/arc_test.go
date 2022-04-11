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

package drkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	cs_drkey "github.com/scionproto/scion/go/pkg/cs/drkey"
)

func TestLvl1ARC(t *testing.T) {

	_, err := cs_drkey.NewLvl1ARC(-10)
	require.Error(t, err)
	cache, err := cs_drkey.NewLvl1ARC(5)
	require.NoError(t, err)

	as0 := addr.MustIAFrom(1, 0)
	cacheKey0 := cs_drkey.Lvl1PrefetchInfo{
		IA:    as0,
		Proto: drkey.Protocol(0),
	}
	cache.Update(cacheKey0)
	assert.Len(t, cache.GetLvl1InfoArray(), 1)

	assert.Contains(t, cache.GetLvl1InfoArray(), cacheKey0)

	for j := 0; j < 4; j++ {
		for i := 0; i < 10; i++ {
			cacheKey := cs_drkey.Lvl1PrefetchInfo{
				IA:    addr.MustIAFrom(1, addr.AS(i)),
				Proto: drkey.Protocol(0),
			}
			cache.Update(cacheKey)
		}
	}
	assert.Len(t, cache.GetLvl1InfoArray(), 5)
	assert.NotContains(t, cache.GetLvl1InfoArray(), cacheKey0)

	as10 := addr.MustIAFrom(1, 10)
	cacheKey10 := cs_drkey.Lvl1PrefetchInfo{
		IA:    as10,
		Proto: drkey.Protocol(0),
	}
	cache.Update(cacheKey10)
	assert.Contains(t, cache.GetLvl1InfoArray(), cacheKey10)
	cache.Update(cacheKey0)
	assert.NotContains(t, cache.GetLvl1InfoArray(), cacheKey10)

}
