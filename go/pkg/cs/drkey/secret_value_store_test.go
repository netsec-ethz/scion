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

package drkey_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	csdrkey "github.com/scionproto/scion/go/pkg/cs/drkey"
)

// waitCondWithTimeout waits for the condition cond and return true, or timeout and return false.
func waitCondWithTimeout(dur time.Duration, cond *sync.Cond) bool {
	ctx, cancelF := context.WithTimeout(context.Background(), dur)
	defer cancelF()
	done := make(chan struct{})
	go func() {
		cond.Wait()
		done <- struct{}{}
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
	}
	return false
}

// TestSecretValueStoreTicker checks that the store starts a ticker to clean expired values.
func TestSecretValueStoreTicker(t *testing.T) {
	var m sync.Mutex
	cond := sync.NewCond(&m)
	m.Lock()
	c := csdrkey.NewSecretValueStore(time.Millisecond)
	// This timeNowFcn is used to mock time.Now() to test expiring entries in the tests below.
	// This _has_ to be called by the cleanup function. Therefore, we can (ab-)use this to check
	// that the background cleaner is indeed running.
	testTimeNowFunc := func() time.Time {
		cond.Broadcast()
		return time.Unix(0, 0)
	}
	c.SetTimeNowFunction(testTimeNowFunc)
	ret := waitCondWithTimeout(time.Minute, cond)
	require.True(t, ret)
}

func TestSecretValueStore(t *testing.T) {
	c := csdrkey.NewSecretValueStore(time.Hour)
	var now atomic.Value
	testTimeNowFunc := func() time.Time {
		return now.Load().(time.Time)
	}
	c.SetTimeNowFunction(testTimeNowFunc)
	now.Store(time.Unix(10, 0))

	k1 := drkey.SV{
		SVMeta: drkey.SVMeta{Epoch: drkey.NewEpoch(10, 12)},
		Key:    drkey.DRKey([]byte{1, 2, 3}),
	}
	c.Set(1, k1)
	c.CleanExpired()
	k, found := c.Get(1)
	require.True(t, found)
	require.Equal(t, k1, k)
	require.Len(t, c.Cache(), 1)

	k2 := drkey.SV{
		SVMeta: drkey.SVMeta{Epoch: drkey.NewEpoch(11, 13)},
		Key:    drkey.DRKey([]byte{2, 3, 4}),
	}
	now.Store(time.Unix(12, 0).Add(-1 * time.Nanosecond))
	c.Set(2, k2)
	require.Len(t, c.Cache(), 2)
	c.CleanExpired()
	require.Len(t, c.Cache(), 2)
	now.Store(time.Unix(12, 1))
	c.CleanExpired()
	require.Len(t, c.Cache(), 1)
	_, found = c.Get(1)
	require.False(t, found)
}

func TestSecretValueFactory(t *testing.T) {
	master := []byte{}
	fac := csdrkey.NewSecretValueFactory(master, 10*time.Second)
	_, err := fac.GetSecretValue(time.Now())
	require.Error(t, err)
	master = []byte{0, 1, 2, 3}
	fac = csdrkey.NewSecretValueFactory(master, 10*time.Second)
	k, err := fac.GetSecretValue(util.SecsToTime(10))
	require.NoError(t, err)
	require.EqualValues(t, 10, k.Epoch.NotBefore.Unix())
	require.EqualValues(t, 20, k.Epoch.NotAfter.Unix())

	now := time.Unix(10, 0)
	k, _ = fac.GetSecretValue(now)
	savedCurrSV := k

	// advance time 9 seconds
	now = now.Add(9 * time.Second)
	k, _ = fac.GetSecretValue(now)
	require.Equal(t, savedCurrSV.Key, k.Key)

	// advance it so we are in total 10 seconds in the future of the original clock
	now = now.Add(time.Second)
	k, _ = fac.GetSecretValue(now)
	require.NotEqual(t, savedCurrSV.Key, k.Key)
	require.Equal(t, savedCurrSV.Epoch.NotAfter, k.Epoch.NotBefore)
}
