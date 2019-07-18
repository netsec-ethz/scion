// Copyright 2018 ETH Zurich
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
	"context"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"

	. "github.com/smartystreets/goconvey/convey"
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

		epoch := drkey.NewEpochFromDuration(util.TimeToSecs(time.Now()), timeOffset)
		sv := &drkey.DRKeySV{Epoch: *epoch}
		SoMsg("drkey", sv, ShouldNotBeNil)
		err := sv.SetKey(asMasterPassword, *epoch)
		SoMsg("drkey", err, ShouldBeNil)
		// TODO: drkeytest: check the key itself?

		drkeyLvl1 := drkey.NewDRKeyLvl1(*epoch, common.RawBytes{},
			addr.IAFromRaw(rawSrcIA), addr.IAFromRaw(rawDstIA))
		err = drkeyLvl1.SetKey(sv.Key)
		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			rows, err := db.InsertDRKeyLvl1(ctx, drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 1)
			rows, err = db.InsertDRKeyLvl1(ctx, drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl1(ctx, drkeyLvl1, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl1.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows = db.GetLvl1Count()
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl1(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl1(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
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
		epoch := drkey.NewEpochFromDuration(util.TimeToSecs(time.Now()), timeOffset)
		drkeyLvl1 := drkey.NewDRKeyLvl1(*epoch, asMasterPassword, srcIA, dstIA)
		drkeyLvl2 := drkey.NewDRKeyLvl2(*drkeyLvl1, drkey.Host2Host, "test",
			addr.HostFromIP(SrcHostIP), addr.HostFromIP(DstHostIP))
		err := drkeyLvl2.SetKey(drkeyLvl1.Key)
		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			rows, err := db.InsertDRKeyLvl2(ctx, drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 1)
			rows, err = db.InsertDRKeyLvl2(ctx, drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl2(ctx, drkeyLvl2, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl2.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows = db.GetLvl2Count()
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl2(ctx, util.TimeToSecs(time.Now().Add(-timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl2(ctx, util.TimeToSecs(time.Now().Add(2*timeOffset*time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestGetMentionedASes(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	var err error
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
			epoch := drkey.NewEpochFromDuration(0, int32(p[2].(int)))
			key := drkey.NewDRKeyLvl1(*epoch, common.RawBytes{}, srcIA, dstIA)
			_, err = db.InsertDRKeyLvl1(ctx, key)
			SoMsg("err", err, ShouldBeNil)
		}

		Convey("Get all of them", func() {
			list, err := db.GetL1SrcASes(ctx)
			SoMsg("err", err, ShouldBeNil)
			expected := []addr.IA{
				ia("1-ff00:0:111"),
				ia("2-ff00:0:211"),
			}
			SoMsg("list", toMap(list), ShouldResemble, toMap(expected))
		})
		Convey("Get valid ones", func() {
			list, err := db.GetValidL1SrcASes(ctx, 3)
			SoMsg("err", err, ShouldBeNil)
			expected := []addr.IA{
				ia("1-ff00:0:111"),
			}
			SoMsg("list", toMap(list), ShouldResemble, toMap(expected))
		})
	})
}

func TestSecretValue(t *testing.T) {
	Convey("Initialization", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		SoMsg("currSV", db.sv.currSV, ShouldBeNil)
		SoMsg("nextSV", db.sv.nextSV, ShouldBeNil)
		var err error
		// no duration or master secret:
		_, err = db.SecretValue()
		SoMsg("err", err, ShouldNotBeNil)

		// no master secret yet
		err = db.SetKeyDuration(10 * time.Second)
		SoMsg("err", err, ShouldBeNil)
		_, err = db.SecretValue()
		SoMsg("err", err, ShouldNotBeNil)

		err = db.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		SoMsg("err", err, ShouldBeNil)
		_, err = db.SecretValue()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("currIdx", db.sv.currIdx, ShouldBeGreaterThan, 0)
		SoMsg("currSV", db.sv.currSV, ShouldNotBeNil)
		SoMsg("nextSV", db.sv.nextSV, ShouldNotBeNil)
	})

	Convey("Epoch", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		now := time.Unix(10, 0)
		db.sv.timeNowFcn = func() time.Time { return now }

		db.SetKeyDuration(10 * time.Second)
		db.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		k, _ := db.SecretValue()
		SoMsg("begin", k.Epoch.Begin, ShouldEqual, 10)
		SoMsg("end", k.Epoch.End, ShouldEqual, 20)
		SoMsg("begin", db.sv.currSV.Epoch.Begin, ShouldEqual, 10)
		SoMsg("end", db.sv.currSV.Epoch.End, ShouldEqual, 20)
		SoMsg("next begin", db.sv.nextSV.Epoch.Begin, ShouldEqual, 20)
		SoMsg("next end", db.sv.nextSV.Epoch.End, ShouldEqual, 30)
	})

	Convey("Key rotation", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		now := time.Unix(10, 0)
		db.sv.timeNowFcn = func() time.Time { return now }

		db.SetKeyDuration(10 * time.Second)
		db.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		db.SecretValue()
		SoMsg("currSV", db.sv.currSV, ShouldNotBeNil)
		SoMsg("nextSV", db.sv.nextSV, ShouldNotBeNil)
		savedCurrIdx := db.sv.currIdx
		savedCurrSV := db.sv.currSV
		savedNextSV := db.sv.nextSV
		// advance time 9 seconds
		now = now.Add(9 * time.Second)
		k, _ := db.SecretValue()
		SoMsg("return value", k, ShouldEqual, savedCurrSV)
		SoMsg("currIdx", db.sv.currIdx, ShouldEqual, savedCurrIdx)
		SoMsg("currSV", db.sv.currSV, ShouldEqual, savedCurrSV)
		SoMsg("nextSV", db.sv.nextSV, ShouldEqual, savedNextSV)
		// advance it so we are in total 10 seconds in the future of the original clock
		now = now.Add(time.Second)
		k, _ = db.SecretValue()
		SoMsg("return value", k, ShouldEqual, savedNextSV)
		SoMsg("currIdx", db.sv.currIdx, ShouldEqual, savedCurrIdx+1)
		SoMsg("currSV", db.sv.currSV, ShouldEqual, savedNextSV)
		SoMsg("nextSV", db.sv.nextSV, ShouldNotBeNil)
		SoMsg("epoch", k.Epoch.Begin, ShouldEqual, savedCurrSV.Epoch.End)
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

func newDatabase(t *testing.T) (*DB, func()) {
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
