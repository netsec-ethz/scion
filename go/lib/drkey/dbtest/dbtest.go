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

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocoltest"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	timeOffset = 10 * 60 // 10 minutes
	timeout    = 3 * time.Second
)

var (
	srcIA   = xtest.MustParseIA("1-ff00:0:111")
	dstIA   = xtest.MustParseIA("1-ff00:0:112")
	srcHost = "192.168.1.37"
	dstHost = "192.168.1.38"
)

type TestableLvl1DB interface {
	drkey.Lvl1DB
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the Lvl1DB interface. An
// implementation of the Lvl1DB interface should at least have one test
// method that calls this test-suite.
func TestLvl1(t *testing.T, db TestableLvl1DB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testDRKeyLvl1(t, db)
}

func testDRKeyLvl1(t *testing.T, db drkey.Lvl1DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(timeOffset * time.Second),
		},
	}
	protoId := drkey.Protocol(0)
	drkeyLvl1 := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)

	lvl1Meta := drkey.Lvl1Meta{
		Validity: time.Now(),
		ProtoId:  protoId,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}

	err := db.InsertLvl1Key(ctx, drkeyLvl1)
	require.NoError(t, err)
	// same key again. It should be okay.
	err = db.InsertLvl1Key(ctx, drkeyLvl1)
	require.NoError(t, err)

	newKey, err := db.GetLvl1Key(ctx, lvl1Meta)
	require.NoError(t, err)
	require.Equal(t, drkeyLvl1.Key, newKey.Key)

	rows, err := db.DeleteExpiredLvl1Keys(ctx,
		time.Now().Add(-timeOffset*time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 0, rows)

	rows, err = db.DeleteExpiredLvl1Keys(ctx,
		time.Now().Add(2*timeOffset*time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)

}

type TestableLvl2DB interface {
	drkey.Lvl2DB
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the Lvl2DB interface. An
// implementation of the Lvl2DB interface should at least have one test
// method that calls this test-suite.
func TestLvl2(t *testing.T, db TestableLvl2DB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testDRKeyLvl2(t, db)
}

func testDRKeyLvl2(t *testing.T, db drkey.Lvl2DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(timeOffset * time.Second),
		},
	}
	protoId := drkey.Protocol(0)
	drkeyLvl1 := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)

	// AS-Host
	as2HostMeta := drkey.ASHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  25,
			SrcIA:    srcIA,
			DstIA:    dstIA,
			Validity: time.Now(),
		},
		DstHost: dstHost,
	}
	asHostKey, err := protocoltest.DeriveASHostGeneric(as2HostMeta, drkeyLvl1)
	require.NoError(t, err)

	err = db.InsertASHostKey(ctx, asHostKey)
	require.NoError(t, err)
	err = db.InsertASHostKey(ctx, asHostKey)
	require.NoError(t, err)

	newKey, err := db.GetASHostKey(ctx, as2HostMeta)
	require.NoError(t, err)
	require.Equal(t, asHostKey.Key, newKey.Key)

	// Host-Host
	h2hMeta := drkey.HostHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  25,
			SrcIA:    srcIA,
			DstIA:    dstIA,
			Validity: time.Now(),
		},
		SrcHost: srcHost,
		DstHost: dstHost,
	}
	h2hKey, err := protocoltest.DeriveHostHostGeneric(h2hMeta, drkeyLvl1)
	require.NoError(t, err)

	err = db.InsertHostHostKey(ctx, h2hKey)
	require.NoError(t, err)
	err = db.InsertHostHostKey(ctx, h2hKey)
	require.NoError(t, err)

	newh2hKey, err := db.GetHostHostKey(ctx, h2hMeta)
	require.NoError(t, err)
	require.Equal(t, h2hKey.Key, newh2hKey.Key)

	_, err = db.DeleteExpiredLvl2Keys(ctx,
		time.Now().Add(-timeOffset*time.Second))
	require.NoError(t, err)

}

type TestableSVDB interface {
	drkey.SecretValueDB
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the SecretValueDB interface. An
// implementation of the SecretValueDB interface should at least have one test
// method that calls this test-suite.
func TestSecretValueDB(t *testing.T, db TestableSVDB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testSecretValue(t, db)
}

func testSecretValue(t *testing.T, db drkey.SecretValueDB) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(timeOffset * time.Second),
		},
	}
	sv, err := drkey.DeriveSV(drkey.Protocol(0), epoch, []byte("0123456789012345"))
	require.NoError(t, err)

	err = db.InsertSV(ctx, sv)
	require.NoError(t, err)
	// same key again. It should be okay.
	err = db.InsertSV(ctx, sv)
	require.NoError(t, err)
	newSV, err := db.GetSV(ctx, drkey.SVMeta{
		ProtoId:  drkey.Protocol(0),
		Validity: time.Now(),
	})
	require.NoError(t, err)
	require.EqualValues(t, sv.Key, newSV.Key)

	rows, err := db.DeleteExpiredSV(ctx,
		time.Now().Add(-timeOffset*time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 0, rows)

	rows, err = db.DeleteExpiredSV(ctx,
		time.Now().Add(2*timeOffset*time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}
