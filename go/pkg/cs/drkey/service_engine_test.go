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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/sqlite"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	cs_drkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	"github.com/scionproto/scion/go/pkg/cs/drkey/mock_drkey"
)

var (
	masterKey = xtest.MustParseHexString("305554050357005ae398259bcdae7468")
	srcIA     = xtest.MustParseIA("1-ff00:0:112")
	dstIA     = xtest.MustParseIA("1-ff00:0:111")
)

func TestGetSV(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()

	store, err := cs_drkey.NewServiceEngine(srcIA, svdb, masterKey, time.Minute, nil, nil, 10)
	require.NoError(t, err)

	meta := drkey.SVMeta{
		ProtoId:  drkey.Generic,
		Validity: util.SecsToTime(0).UTC(),
	}

	rcvKey1, err := store.GetSecretValue(context.Background(), meta)
	require.NoError(t, err)
	meta.Validity = util.SecsToTime(1).UTC()
	rcvKey2, err := store.GetSecretValue(context.Background(), meta)
	require.NoError(t, err)
	assert.EqualValues(t, rcvKey1, rcvKey2)
	meta.Validity = util.SecsToTime(61).UTC()
	rcvKey3, err := store.GetSecretValue(context.Background(), meta)
	require.NoError(t, err)
	assert.NotEqualValues(t, rcvKey1, rcvKey3)
}

func TestDeriveLvl1Key(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()

	store, err := cs_drkey.NewServiceEngine(srcIA, svdb, masterKey, time.Minute, nil, nil, 10)
	require.NoError(t, err)

	meta := drkey.Lvl1Meta{
		DstIA:    dstIA,
		ProtoId:  drkey.Protocol(0),
		Validity: time.Now(),
	}

	_, err = store.DeriveLvl1(meta)
	require.NoError(t, err)
}

func TestGetLvl1Key(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()
	lvl1db := newLvl1Database(t)
	defer lvl1db.Close()
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	firstLvl1Key := drkey.Lvl1Key{
		Epoch:   drkey.NewEpoch(0, 2),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: drkey.Generic,
	}
	copy(firstLvl1Key.Key[:], k)
	secondLvl1Key := drkey.Lvl1Key{
		Epoch:   drkey.NewEpoch(2, 4),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: drkey.Generic,
	}
	copy(secondLvl1Key.Key[:], k)
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	fetcher := mock_drkey.NewMockFetcher(mctrl)
	firstCall := fetcher.EXPECT().FetchLvl1(gomock.Any(),
		gomock.Any()).Return(firstLvl1Key, nil)
	secondCall := fetcher.EXPECT().FetchLvl1(gomock.Any(),
		gomock.Any()).Return(secondLvl1Key, nil).After(firstCall)
	fetcher.EXPECT().FetchLvl1(gomock.Any(),
		gomock.Any()).Return(drkey.Lvl1Key{},
		serrors.New("error retrieving key")).After(secondCall)

	cache := mock_drkey.NewMockLvl1PrefetchListKeeper(mctrl)
	// It must be called exactly 3 times
	cache.EXPECT().Update(gomock.Any()).Times(3)

	store := cs_drkey.NewTestServiceEngine(dstIA, svdb, masterKey,
		time.Minute, lvl1db, fetcher, cache)

	// it must fetch first key from remote
	rcvKey1, err := store.GetLvl1Key(context.Background(), drkey.Lvl1Meta{
		ProtoId:  firstLvl1Key.ProtoId,
		DstIA:    firstLvl1Key.DstIA,
		SrcIA:    firstLvl1Key.SrcIA,
		Validity: util.SecsToTime(0).UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, firstLvl1Key, rcvKey1)
	// it must not fetch key from remote and return previous key
	rcvKey2, err := store.GetLvl1Key(context.Background(), drkey.Lvl1Meta{
		ProtoId:  firstLvl1Key.ProtoId,
		DstIA:    firstLvl1Key.DstIA,
		SrcIA:    firstLvl1Key.SrcIA,
		Validity: util.SecsToTime(1).UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, firstLvl1Key, rcvKey2)
	// it must fetch second key from remote
	rcvKey3, err := store.GetLvl1Key(context.Background(), drkey.Lvl1Meta{
		ProtoId:  firstLvl1Key.ProtoId,
		DstIA:    firstLvl1Key.DstIA,
		SrcIA:    firstLvl1Key.SrcIA,
		Validity: util.SecsToTime(3).UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, secondLvl1Key, rcvKey3)
	//Simulate a call coming from the prefetcher, it must not update cache
	pref_ctx := context.WithValue(context.Background(), "from_prefetcher", true)
	rcvKey4, err := store.GetLvl1Key(pref_ctx, drkey.Lvl1Meta{
		ProtoId:  firstLvl1Key.ProtoId,
		DstIA:    firstLvl1Key.DstIA,
		SrcIA:    firstLvl1Key.SrcIA,
		Validity: util.SecsToTime(3).UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, secondLvl1Key, rcvKey4)
	// This call returns an error, hence the cache must not be updated
	_, err = store.GetLvl1Key(context.Background(), drkey.Lvl1Meta{
		ProtoId:  firstLvl1Key.ProtoId,
		DstIA:    firstLvl1Key.DstIA,
		SrcIA:    firstLvl1Key.SrcIA,
		Validity: util.SecsToTime(5).UTC(),
	})
	require.Error(t, err)
	//Requesting local key should not update the cache
	locallvl1Meta := drkey.Lvl1Meta{
		SrcIA:    dstIA,
		DstIA:    xtest.MustParseIA("1-ff00:0:111"),
		ProtoId:  drkey.Generic,
		Validity: util.SecsToTime(1).UTC(),
	}
	_, err = store.GetLvl1Key(context.Background(), locallvl1Meta)
	require.NoError(t, err)

}

func newLvl1Database(t *testing.T) *sqlite.Lvl1Backend {
	db, err := sqlite.NewLvl1Backend("file::memory:")
	require.NoError(t, err)

	return db
}

func newSVDatabase(t *testing.T) *sqlite.SVBackend {
	db, err := sqlite.NewSVBackend("file::memory:")
	require.NoError(t, err)

	return db
}
