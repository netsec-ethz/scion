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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
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
	Convey("Initialize DB and derive DRKey", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		epoch := drkey.Epoch{Begin: time.Now(), End: time.Now().Add(timeOffset * time.Second)}
		sv, err := drkey.NewSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
		SoMsg("drkey", sv, ShouldNotBeNil)
		SoMsg("drkey", err, ShouldBeNil)

		drkeyLvl1, err := drkey.NewLvl1Key(drkey.Lvl1Meta{
			Epoch: epoch,
			SrcIA: addr.IAFromRaw(rawSrcIA),
			DstIA: addr.IAFromRaw(rawDstIA)}, sv)
		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			err := db.InsertLvl1Key(ctx, drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)
			// same key again. It should be okay.
			err = db.InsertLvl1Key(ctx, drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)

			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetLvl1Key(ctx, drkeyLvl1.Lvl1Meta, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl1.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows, err := db.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 1)
			})
		})
	})
}

func TestDRKeyLvl2(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	Convey("Initialize DB and derive DRKey", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		srcIA := addr.IAFromRaw(rawSrcIA)
		dstIA := addr.IAFromRaw(rawDstIA)
		epoch := drkey.Epoch{Begin: time.Now(), End: time.Now().Add(timeOffset * time.Second)}
		sv, err := drkey.NewSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
		SoMsg("drkey", sv, ShouldNotBeNil)
		SoMsg("drkey", err, ShouldBeNil)
		drkeyLvl1, err := drkey.NewLvl1Key(drkey.Lvl1Meta{
			Epoch: epoch,
			SrcIA: srcIA,
			DstIA: dstIA,
		}, sv)
		SoMsg("drkey", err, ShouldBeNil)

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

		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			err := db.InsertLvl2Key(ctx, drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			err = db.InsertLvl2Key(ctx, drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetLvl2Key(ctx, drkeyLvl2.Lvl2Meta, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl2.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows, err := db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestGetMentionedASes(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	Convey("Insert many rows", t, func() {
		db, cleanF := newDatabase(t)
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
				Begin: begin,
				End:   begin.Add(time.Duration(p[2].(int)) * time.Second),
			}
			sv, err := drkey.NewSV(drkey.SVMeta{Epoch: epoch}, asMasterPassword)
			SoMsg("drkey", sv, ShouldNotBeNil)
			SoMsg("drkey", err, ShouldBeNil)
			key, err := drkey.NewLvl1Key(drkey.Lvl1Meta{
				Epoch: epoch,
				SrcIA: srcIA,
				DstIA: dstIA,
			}, sv)
			SoMsg("drkey", err, ShouldBeNil)
			err = db.InsertLvl1Key(ctx, key)
			SoMsg("err", err, ShouldBeNil)
		}

		Convey("Get all of them", func() {
			list, err := db.GetLvl1SrcASes(ctx)
			SoMsg("err", err, ShouldBeNil)
			expected := []addr.IA{
				ia("1-ff00:0:111"),
				ia("2-ff00:0:211"),
			}
			SoMsg("list", toMap(list), ShouldResemble, toMap(expected))
		})
		Convey("Get valid ones", func() {
			list, err := db.GetValidLvl1SrcASes(ctx, 3)
			SoMsg("err", err, ShouldBeNil)
			expected := []addr.IA{
				ia("1-ff00:0:111"),
			}
			SoMsg("list", toMap(list), ShouldResemble, toMap(expected))
		})
	})
}

func toMap(list []addr.IA) map[addr.IA]struct{} {
	set := map[addr.IA]struct{}{}
	for _, i := range list {
		set[i] = struct{}{}
	}
	return set
}

func ia(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic("Invalid value")
	}
	return ia
}

func newDatabase(t *testing.T) (*Backend, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		t.Fatalf("unable to create temp file")
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close temp file")
	}
	db, err := New(name)
	if err != nil {
		t.Fatalf("unable to initialize database")
	}
	return db, func() {
		db.Close()
		os.Remove(name)
	}
}
