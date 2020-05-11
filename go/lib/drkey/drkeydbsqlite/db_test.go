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

package drkeydbsqlite

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	timeOffset = 10 * 60 // 10 minutes
)

var (
	asMasterPassword = []byte("0123456789012345")
	rawSrcIA         = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x77}
	rawDstIA         = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x88}
	SrcHostIP        = net.IPv4(192, 168, 1, 37)
	DstHostIP        = net.IPv4(192, 168, 1, 38)
)

func TestDRKeyLvl1(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	db, cleanF := newLvl1Database(t)
	defer cleanF()

	epoch := drkey.Epoch{
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Now()},
			NotAfter:  util.UnixTime{Time: time.Now().Add(timeOffset * time.Second)},
		},
	}
	sv, err := drkey.DeriveSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
	require.NoError(t, err)

	drkeyLvl1, err := protocol.DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: addr.IAFromRaw(rawSrcIA),
		DstIA: addr.IAFromRaw(rawDstIA)}, sv)
	require.NoError(t, err)

	err = db.InsertLvl1Key(ctx, drkeyLvl1)
	require.NoError(t, err)
	// same key again. It should be okay.
	err = db.InsertLvl1Key(ctx, drkeyLvl1)
	require.NoError(t, err)

	newKey, err := db.GetLvl1Key(ctx, drkeyLvl1.Lvl1Meta, util.TimeToSecs(time.Now()))
	require.NoError(t, err)
	require.Equal(t, drkeyLvl1.Key, newKey.Key)

	rows, err := db.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
	require.NoError(t, err)
	require.EqualValues(t, 0, rows)

	rows, err = db.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)

}

func TestDRKeyLvl2(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	db, cleanF := newLvl2Database(t)
	defer cleanF()

	srcIA := addr.IAFromRaw(rawSrcIA)
	dstIA := addr.IAFromRaw(rawDstIA)
	epoch := drkey.Epoch{
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Now()},
			NotAfter:  util.UnixTime{Time: time.Now().Add(timeOffset * time.Second)},
		},
	}
	sv, err := drkey.DeriveSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
	require.NoError(t, err)
	drkeyLvl1, err := protocol.DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}, sv)
	require.NoError(t, err)

	standardImpl := protocol.Standard{}
	drkeyLvl2, err := standardImpl.DeriveLvl2(drkey.Lvl2Meta{
		KeyType:  drkey.Host2Host,
		Protocol: "test",
		Epoch:    epoch,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  addr.HostFromIP(SrcHostIP),
		DstHost:  addr.HostFromIP(DstHostIP),
	}, drkeyLvl1)
	require.NoError(t, err)

	err = db.InsertLvl2Key(ctx, drkeyLvl2)
	require.NoError(t, err)
	err = db.InsertLvl2Key(ctx, drkeyLvl2)
	require.NoError(t, err)

	newKey, err := db.GetLvl2Key(ctx, drkeyLvl2.Lvl2Meta, util.TimeToSecs(time.Now()))
	require.NoError(t, err)
	require.Equal(t, drkeyLvl2.Key, newKey.Key)

	rows, err := db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
	require.NoError(t, err)
	require.EqualValues(t, 0, rows)

	rows, err = db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

func TestGetMentionedASes(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	db, cleanF := newLvl1Database(t)
	defer cleanF()

	pairsL1 := [][]interface{}{
		{"1-ff00:0:111", "1-ff00:0:112", 1},
		{"1-ff00:0:111", "1-ff00:0:110", 10},
		{"2-ff00:0:211", "1-ff00:0:113", 1},
	}
	for _, p := range pairsL1 {
		srcIA, _ := addr.IAFromString(p[0].(string))
		dstIA, _ := addr.IAFromString(p[1].(string))
		begin := time.Unix(0, 0)
		epoch := drkey.Epoch{
			Validity: scrypto.Validity{
				NotBefore: util.UnixTime{Time: begin},
				NotAfter:  util.UnixTime{Time: begin.Add(time.Duration(p[2].(int)) * time.Second)},
			},
		}
		sv, err := drkey.DeriveSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
		require.NoError(t, err)

		key, err := protocol.DeriveLvl1(drkey.Lvl1Meta{
			Epoch: epoch,
			SrcIA: srcIA,
			DstIA: dstIA,
		}, sv)
		require.NoError(t, err)

		err = db.InsertLvl1Key(ctx, key)
		require.NoError(t, err)
	}

	list, err := db.GetLvl1SrcASes(ctx)
	require.NoError(t, err)

	expected := []addr.IA{
		ia("1-ff00:0:111"),
		ia("2-ff00:0:211"),
	}

	list, err = db.GetValidLvl1SrcASes(ctx, 3)
	require.NoError(t, err)

	expected = []addr.IA{
		ia("1-ff00:0:111"),
	}
	require.Equal(t, expected, list)
}

func ia(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic("Invalid value")
	}
	return ia
}

func newLvl1Database(t *testing.T) (*Lvl1Backend, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := NewLvl1Backend(name)
	require.NoError(t, err)

	return db, func() {
		db.Close()
		os.Remove(name)
	}
}

func newLvl2Database(t *testing.T) (*Lvl2Backend, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := NewLvl2Backend(name)
	require.NoError(t, err)

	return db, func() {
		db.Close()
		os.Remove(name)
	}
}
