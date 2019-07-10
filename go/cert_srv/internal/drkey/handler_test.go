// Copyright 2019 Anapaya Systems
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
	"context"
	"encoding/hex"
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/keystore/mock_keystore"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
)

func TestDeriveLvl1Key(t *testing.T) {
	Convey("Derive a Level 1 DRKey", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		sv := getTestSV()
		expectedKey, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5")
		lvl1Key, err := deriveLvl1Key(srcIA, dstIA, sv)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("key", lvl1Key.Key, ShouldResemble, (common.RawBytes)(expectedKey))
	})
}

func TestValidateLvl1Request(t *testing.T) {
	Convey("Validate a level 1 request", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		err := validateReq(srcIA, dstIA)
		SoMsg("err", err, ShouldBeNil)
	})
}

func TestLevel1KeyBuildReply(t *testing.T) {
	Convey("Construct a Level 1 DRKey reply", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		sv := getTestSV()
		certA := loadCert("testdata/as-A.crt", t)
		privateKeyA, _ := keyconf.LoadKey("testdata/asA-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
		certB := loadCert("testdata/as-B.crt", t)
		privateKeyB, _ := keyconf.LoadKey("testdata/asB-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
		expectedDerivedKey, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5")
		reply, err := Level1KeyBuildReply(srcIA, dstIA, sv, certB, privateKeyA)
		SoMsg("err", err, ShouldBeNil)
		decryptedKey, err := drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, certB.SubjectEncKey, privateKeyB)
		SoMsg("err", err, ShouldNotBeNil)
		decryptedKey, err = drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, certA.SubjectEncKey, privateKeyB)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("decryptedKey", decryptedKey.Key, ShouldResemble, (common.RawBytes)(expectedDerivedKey))
		SoMsg("srcIA", decryptedKey.SrcIA, ShouldResemble, srcIA)
		SoMsg("dstIA", decryptedKey.DstIA, ShouldResemble, dstIA)
		SoMsg("Epoch", reply.Epoch(), ShouldResemble, sv.Epoch)
	})
}

func TestLevel1KeyFromReply(t *testing.T) {
	Convey("Get Level 1 key from reply", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		sv := getTestSV()
		certA := loadCert("testdata/as-A.crt", t)
		privateKeyA, _ := keyconf.LoadKey("testdata/asA-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
		certB := loadCert("testdata/as-B.crt", t)
		privateKeyB, _ := keyconf.LoadKey("testdata/asB-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
		expectedKey, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5")
		reply, err := Level1KeyBuildReply(srcIA, dstIA, sv, certB, privateKeyA)
		SoMsg("err", err, ShouldBeNil)
		gotKey, err := Level1KeyFromReply(reply, srcIA, certA, privateKeyB)
		SoMsg("key", gotKey.Key, ShouldResemble, (common.RawBytes)(expectedKey))
		SoMsg("srcIA", gotKey.SrcIA, ShouldResemble, srcIA)
		SoMsg("dstIA", gotKey.DstIA, ShouldResemble, dstIA)
		SoMsg("Epoch", gotKey.Epoch, ShouldResemble, sv.Epoch)
	})
}

func TestDeriveLvl2Key(t *testing.T) {
	Convey("Derive a Level 2 DRKey", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		k, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5") // just a level 1 key
		sv := getTestSV()
		sv.Key = k
		lvl1Key := &drkey.DRKeyLvl1{
			DRKey: drkey.DRKey(*sv),
			SrcIA: srcIA,
			DstIA: dstIA,
		}
		var srcHost addr.HostAddr = addr.HostNone{}
		var dstHost addr.HostAddr = addr.HostNone{}
		lvl2Key, err := deriveLvl2Key(lvl1Key, drkey.AS2AS, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		expectedLvl2Key, _ := hex.DecodeString("03666f6fbc92eb6adcf36df6263a26254ca5209e")
		SoMsg("lvl2Key", lvl2Key.Key, ShouldResemble, common.RawBytes(expectedLvl2Key))
		// different protocol should affect the output:
		lvl2Key, err = deriveLvl2Key(lvl1Key, drkey.AS2AS, "bar", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
		// as2host and empty host address should error:
		lvl2Key, err = deriveLvl2Key(lvl1Key, drkey.AS2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldNotBeNil)
		// different type should affect the output:
		dstHost = addr.HostFromIPStr("127.0.0.1")
		lvl2Key, err = deriveLvl2Key(lvl1Key, drkey.AS2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
		// when host 2 host both host addresses must be set
		lvl2Key, err = deriveLvl2Key(lvl1Key, drkey.Host2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldNotBeNil)
		srcHost = addr.HostFromIPStr("127.0.0.1")
		lvl2Key, err = deriveLvl2Key(lvl1Key, drkey.Host2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
	})
}

func TestLevel2KeyBuildReply(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	Convey("Derive a Level 2 DRKey with src AS here", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		h := &Level2ReqHandler{IA: srcIA}
		sv := getTestSV()
		req := &drkey_mgmt.DRKeyLvl2Req{
			Protocol: "foo",
			ReqType:  uint8(drkey.AS2AS),
			ValTime:  0,
			SrcHost:  *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
			DstHost:  *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
		}
		reply, err := h.level2KeyBuildReply(ctx, req, srcIA, dstIA, sv)
		SoMsg("err", err, ShouldBeNil)
		expectedLvl2Key, _ := hex.DecodeString("03666f6fbc92eb6adcf36df6263a26254ca5209e")
		SoMsg("lvl2Key", reply.DRKey, ShouldResemble, common.RawBytes(expectedLvl2Key))
	})

	Convey("Obtain a Level 2 DRKey with fast path in another AS", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:2")
		dstIA, _ := addr.IAFromString("1-ff00:0:1")

		sv := getTestSV()
		req := &drkey_mgmt.DRKeyLvl2Req{
			Protocol: "foo",
			ReqType:  uint8(drkey.AS2AS),
			ValTime:  0,
			SrcHost:  *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
			DstHost:  *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
		}
		Convey("Key in DB", func() {
			ctrl, _, db, handler := setup(t, dstIA)
			defer ctrl.Finish()
			// mock a key in the DB
			drkeyLvl2 := drkey.NewDRKeyLvl2(drkey.NewDRKeyLvl1(sv.Epoch, sv.Key, srcIA, dstIA),
				drkey.AS2AS, "foo", addr.HostNone{}, addr.HostNone{})
			db.EXPECT().GetDRKeyLvl2(gomock.Any(), uint32(0)).Return(drkeyLvl2, nil).Do(
				func(argKey *drkey.DRKeyLvl2, argValTime uint32) {
					if argKey.DRKeyLvl1.SrcIA != srcIA ||
						argKey.DRKeyLvl1.DstIA != dstIA ||
						argKey.Protocol != "foo" || argKey.KeyType != drkey.AS2AS ||
						!argKey.SrcHost.Equal(drkeyLvl2.SrcHost) ||
						!argKey.DstHost.Equal(drkeyLvl2.DstHost) {
						SoMsg("Unexpected requested key to the DB", argKey, ShouldBeTrue)
					}
				})
			reply, err := handler.level2KeyBuildReply(ctx, req, srcIA, dstIA, sv)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply.DRKey", reply.DRKey, ShouldResemble, sv.Key)
		})
		Convey("key not in DB, relay on CS_{srcIA}", func() {
			ctrl, msger, db, handler := setup(t, dstIA)
			defer ctrl.Finish()
			db.EXPECT().GetDRKeyLvl2(gomock.Any(), gomock.Any()).Return(nil, nil)
			csSrcAddr := &snet.Addr{IA: srcIA, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
			msger.EXPECT().RequestDRKeyLvl2(gomock.Any(), gomock.Any(), csSrcAddr, gomock.Any())
			handler.level2KeyBuildReply(ctx, req, srcIA, dstIA, sv)
		})
	})
}

func getTestSV() *drkey.DRKeySV {
	return &drkey.DRKeySV{
		Epoch: drkey.Epoch{
			Begin: 0,
			End:   1,
		},
		Key: common.RawBytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
}

func loadCert(filename string, t *testing.T) *cert.Certificate {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Unable to load raw from '%s': %v", filename, err)
	}
	trc, err := cert.CertificateFromRaw(b)
	if err != nil {
		t.Fatalf("Error loading Certificate from '%s': %v", filename, err)
	}
	return trc
}

func setup(t *testing.T, thisIA addr.IA) (*gomock.Controller, *mock_infra.MockMessenger, *mock_keystore.MockDRKeyStore, *Level2ReqHandler) {
	ctrl := gomock.NewController(t)
	msger := mock_infra.NewMockMessenger(ctrl)
	db := mock_keystore.NewMockDRKeyStore(ctrl)
	// TODO drkeytest: we should have a mock also for DRKeystore

	handler := &Level2ReqHandler{
		State: &config.State{
			DRKeyStore: db,
		},
		IA:    thisIA,
		Msger: msger,
	}
	return ctrl, msger, db, handler
}
