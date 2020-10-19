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
	"github.com/scionproto/scion/go/lib/drkey/drkeydbsqlite"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	cs_drkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	"github.com/scionproto/scion/go/pkg/cs/drkey/mock_drkey"
	"github.com/scionproto/scion/go/pkg/cs/drkey/test"
)

func TestDeriveLvl1Key(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:112")
	dstIA := xtest.MustParseIA("1-ff00:0:111")
	expectedKey := xtest.MustParseHexString("87ee10bcc9ef1501783949a267f8ec6b")

	store := cs_drkey.ServiceStore{
		LocalIA:      srcIA,
		SecretValues: test.GetSecretValueTestFactory(),
	}
	lvl1Key, err := store.DeriveLvl1(dstIA, time.Now())
	require.NoError(t, err)
	require.EqualValues(t, expectedKey, lvl1Key.Key)
}

func TestGetLvl1Key(t *testing.T) {
	lvl1db := newLvl1Database(t)
	defer lvl1db.Close()
	localIA := xtest.MustParseIA("1-ff00:0:110")
	dstIA := localIA
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	firstLvl1Key := drkey.Lvl1Key{
		Key: k,
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(0, 2),
			SrcIA: srcIA,
			DstIA: dstIA,
		},
	}
	secondLvl1Key := drkey.Lvl1Key{
		Key: k,
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(2, 4),
			SrcIA: srcIA,
			DstIA: dstIA,
		},
	}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	fetcher := mock_drkey.NewMockFetcher(mctrl)
	firstCall := fetcher.EXPECT().GetLvl1FromOtherCS(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Return(firstLvl1Key, nil)
	fetcher.EXPECT().GetLvl1FromOtherCS(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Return(secondLvl1Key, nil).After(firstCall)

	store := &cs_drkey.ServiceStore{
		LocalIA: localIA,
		DB:      lvl1db,
		Fetcher: fetcher,
	}

	// it must fetch first key from remote
	rcvKey1, err := store.GetLvl1Key(context.Background(), firstLvl1Key.Lvl1Meta,
		util.SecsToTime(0).UTC())
	require.NoError(t, err)
	assert.Equal(t, firstLvl1Key, rcvKey1)
	// it must not fetch key from remote and return previous key
	rcvKey2, err := store.GetLvl1Key(context.Background(), firstLvl1Key.Lvl1Meta,
		util.SecsToTime(1).UTC())
	require.NoError(t, err)
	assert.Equal(t, firstLvl1Key, rcvKey2)
	// it must fetch second key from remote
	rcvKey3, err := store.GetLvl1Key(context.Background(), firstLvl1Key.Lvl1Meta,
		util.SecsToTime(3).UTC())
	require.NoError(t, err)
	assert.Equal(t, secondLvl1Key, rcvKey3)
}

func newLvl1Database(t *testing.T) *drkeydbsqlite.Lvl1Backend {
	db, err := drkeydbsqlite.NewLvl1Backend("file::memory:")
	require.NoError(t, err)

	return db
}
