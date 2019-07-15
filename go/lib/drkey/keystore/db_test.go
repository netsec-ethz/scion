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
			rows, err := db.InsertDRKeyLvl1(drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 1)
			rows, err = db.InsertDRKeyLvl1(drkeyLvl1)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl1(drkeyLvl1, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl1.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows = db.GetLvl1Count()
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl1(util.TimeToSecs(time.Now().Add(-timeOffset * time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl1(util.TimeToSecs(time.Now().Add(2 * timeOffset * time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestDRKeyLvl2(t *testing.T) {
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
			rows, err := db.InsertDRKeyLvl2(drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 1)
			rows, err = db.InsertDRKeyLvl2(drkeyLvl2)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl2(drkeyLvl2, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey.Key, ShouldResemble, drkeyLvl2.Key)
			})

			Convey("Remove outdated drkeys", func() {
				rows = db.GetLvl2Count()
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl2(util.TimeToSecs(time.Now().Add(-timeOffset * time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl2(util.TimeToSecs(time.Now().Add(2 * timeOffset * time.Second)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			})
		})
	})
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
