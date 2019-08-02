// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage/mock_drkeystorage"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/mock_trustdb"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
)

func TestDeriveLvl1Key(t *testing.T) {
	Convey("Derive a Level 1 DRKey", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:1")
		dstIA, _ := addr.IAFromString("1-ff00:0:2")
		sv := getTestSV()
		expectedKey, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5")
		lvl1Key, err := deriveLvl1Key(srcIA, dstIA, &sv)
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

func TestLvl1KeyBuildReply(t *testing.T) {
	Convey("Construct a Level 1 DRKey reply", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:112")
		dstIA, _ := addr.IAFromString("1-ff00:0:111")
		sv := getTestSV()
		cert111, privateKey111, cert112, privateKey112 := loadCertsKeys(t)
		expectedDerivedKey, _ := hex.DecodeString("714408025fd6d0024abb172ae19b377d")
		reply, err := Lvl1KeyBuildReply(srcIA, dstIA, &sv, cert111, privateKey112)
		SoMsg("err", err, ShouldBeNil)
		decryptedKey, err := drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert111.SubjectEncKey, privateKey111)
		SoMsg("err", err, ShouldNotBeNil)
		decryptedKey, err = drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert112.SubjectEncKey, privateKey111)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("decryptedKey", decryptedKey.Key, ShouldResemble, (common.RawBytes)(expectedDerivedKey))
		SoMsg("srcIA", decryptedKey.SrcIA, ShouldResemble, srcIA)
		SoMsg("dstIA", decryptedKey.DstIA, ShouldResemble, dstIA)
		SoMsg("Epoch", reply.Epoch(), ShouldResemble, sv.Epoch)
	})
}

func TestLvl1KeyFromReply(t *testing.T) {
	Convey("Get Level 1 key from reply", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:112")
		dstIA, _ := addr.IAFromString("1-ff00:0:111")
		sv := getTestSV()
		cert111, privateKey111, cert112, privateKey112 := loadCertsKeys(t)
		expectedKey, _ := hex.DecodeString("714408025fd6d0024abb172ae19b377d")
		reply, err := Lvl1KeyBuildReply(srcIA, dstIA, &sv, cert111, privateKey112)
		SoMsg("err", err, ShouldBeNil)
		gotKey, err := Lvl1KeyFromReply(reply, srcIA, cert112, privateKey111)
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
		ctrl, _, _, _, handler := setupHandler(t, srcIA, "")
		defer ctrl.Finish()

		k, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5") // just a level 1 key
		sv := getTestSV()
		sv.Key = k
		lvl1Key := drkey.Lvl1Key{
			DRKey: drkey.DRKey{Key: k},
			Lvl1Meta: drkey.Lvl1Meta{
				Epoch: sv.Epoch,
				SrcIA: srcIA,
				DstIA: dstIA,
			},
		}
		var srcHost addr.HostAddr = addr.HostNone{}
		var dstHost addr.HostAddr = addr.HostNone{}
		lvl2Key, err := handler.deriveLvl2Key(lvl1Key, drkey.AS2AS, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		expectedLvl2Key, _ := hex.DecodeString("03666f6fbc92eb6adcf36df6263a26254ca5209e")
		SoMsg("lvl2Key", lvl2Key.Key, ShouldResemble, common.RawBytes(expectedLvl2Key))
		// different protocol should affect the output:
		lvl2Key, err = handler.deriveLvl2Key(lvl1Key, drkey.AS2AS, "bar", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
		// as2host and empty host address should error:
		lvl2Key, err = handler.deriveLvl2Key(lvl1Key, drkey.AS2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldNotBeNil)
		// different type should affect the output:
		dstHost = addr.HostFromIPStr("127.0.0.1")
		lvl2Key, err = handler.deriveLvl2Key(lvl1Key, drkey.AS2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
		// when host 2 host both host addresses must be set
		lvl2Key, err = handler.deriveLvl2Key(lvl1Key, drkey.Host2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldNotBeNil)
		srcHost = addr.HostFromIPStr("127.0.0.1")
		lvl2Key, err = handler.deriveLvl2Key(lvl1Key, drkey.Host2Host, "foo", srcHost, dstHost)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", lvl2Key.Key, ShouldNotResemble, common.RawBytes(expectedLvl2Key))
	})
}

func TestLvl2KeyBuildReply(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	Convey("Derive a Level 2 DRKey (this CS is in the src AS)", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:112")
		dstIA, _ := addr.IAFromString("1-ff00:0:111")
		ctrl, _, _, store, handler := setupHandler(t, srcIA, "")
		defer ctrl.Finish()

		sv := getTestSV()
		req := &drkey_mgmt.DRKeyLvl2Req{
			Protocol:   "foo",
			ReqType:    uint8(drkey.AS2AS),
			ValTimeRaw: 0,
			SrcHost:    *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
			DstHost:    *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
		}
		// expectedLvl2Key, _ := hex.DecodeString("03666f6fd03e93e69f72993b0e5613283e631017")
		expectedLvl2Key, _ := hex.DecodeString("d03e93e69f72993b0e5613283e631017")
		drkeyLvl2, err := protocol.StandardImpl.DeriveLvl2(drkey.Lvl2Meta{
			Epoch:    sv.Epoch,
			SrcIA:    srcIA,
			DstIA:    dstIA,
			KeyType:  drkey.AS2AS,
			Protocol: "foo",
			SrcHost:  addr.HostNone{},
			DstHost:  addr.HostNone{},
		}, drkey.Lvl1Key{
			Lvl1Meta: drkey.Lvl1Meta{
				Epoch: sv.Epoch,
				SrcIA: srcIA,
				DstIA: dstIA,
			},
			DRKey: drkey.DRKey{Key: expectedLvl2Key},
		})
		SoMsg("err", err, ShouldBeNil)
		store.EXPECT().InsertLvl2Key(ctx, drkeyLvl2).Return(nil)
		reply, err := handler.lvl2KeyBuildReply(ctx, req, srcIA, dstIA, &sv)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("lvl2Key", reply.DRKeyRaw, ShouldResemble, common.RawBytes(expectedLvl2Key))
	})

	Convey("Obtain a Level 2 DRKey with fast path in another AS", t, func() {
		srcIA, _ := addr.IAFromString("1-ff00:0:112")
		dstIA, _ := addr.IAFromString("1-ff00:0:111")
		cert111, _, _, privateKey112 := loadCertsKeys(t)

		sv := getTestSV()
		req := &drkey_mgmt.DRKeyLvl2Req{
			Protocol:   "foo",
			ReqType:    uint8(drkey.AS2AS),
			ValTimeRaw: 0,
			SrcHost:    *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
			DstHost:    *drkey_mgmt.NewDRKeyHost(addr.HostNone{}),
		}
		drkeyLvl2, err := protocol.StandardImpl.DeriveLvl2(drkey.Lvl2Meta{
			Epoch:    sv.Epoch,
			SrcIA:    srcIA,
			DstIA:    dstIA,
			KeyType:  drkey.AS2AS,
			Protocol: "foo",
			SrcHost:  addr.HostNone{},
			DstHost:  addr.HostNone{},
		}, drkey.Lvl1Key{
			Lvl1Meta: drkey.Lvl1Meta{
				Epoch: sv.Epoch,
				SrcIA: srcIA,
				DstIA: dstIA,
			},
			DRKey: drkey.DRKey{Key: sv.DRKey.Key},
		})
		SoMsg("err", err, ShouldBeNil)
		Convey("Key L2 in DB", func() {
			ctrl, _, _, store, handler := setupHandler(t, dstIA, "")
			defer ctrl.Finish()
			// mock a key in the DB
			store.EXPECT().GetLvl2Key(ctx, gomock.Any(), uint32(0)).Return(drkeyLvl2, nil).Do(
				func(ctx context.Context, argKey *drkey.Lvl2Key, argValTime uint32) {
					if argKey.Lvl2Meta.SrcIA != srcIA ||
						argKey.Lvl2Meta.DstIA != dstIA ||
						argKey.Protocol != "foo" || argKey.KeyType != drkey.AS2AS ||
						!argKey.SrcHost.Equal(drkeyLvl2.SrcHost) ||
						!argKey.DstHost.Equal(drkeyLvl2.DstHost) {
						SoMsg("Unexpected requested key to the DB", argKey, ShouldBeTrue)
					}
				})
			reply, err := handler.lvl2KeyBuildReply(ctx, req, srcIA, dstIA, &sv)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply.DRKey", reply.DRKeyRaw, ShouldResemble, sv.Key)
		})

		Convey("key not in DB, L1 in DB, expect derivation", func() {
			ctrl, _, _, drkeyStore, handler := setupHandler(t, dstIA, "testdata/as112/")
			defer ctrl.Finish()
			lvl1Key, err := deriveLvl1Key(srcIA, dstIA, &sv)
			SoMsg("err", err, ShouldBeNil)
			expectedLvl2Key, _ := hex.DecodeString("03666f6fd03e93e69f72993b0e5613283e631017")
			drkeyLvl2.DRKey.Key = expectedLvl2Key
			drkeyStore.EXPECT().GetLvl2Key(ctx, gomock.Any(), gomock.Any()).Return(nil, nil)
			drkeyStore.EXPECT().GetLvl1Key(ctx, &drkey.Lvl1Meta{SrcIA: srcIA, DstIA: dstIA}, req.ValTimeRaw).Return(lvl1Key, nil)
			drkeyStore.EXPECT().InsertLvl2Key(ctx, drkeyLvl2).Return(nil)
			reply, err := handler.lvl2KeyBuildReply(ctx, req, srcIA, dstIA, &sv)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply.DRKey", reply.DRKeyRaw, ShouldResemble, common.RawBytes(expectedLvl2Key))
		})

		Convey("key not in DB, relay on CS_{srcIA}", func() {
			ctrl, msger, trustDB, store, handler := setupHandler(t, dstIA, "testdata/as112/")
			defer ctrl.Finish()
			csSrcAddr := &snet.Addr{IA: srcIA, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
			replyFromOtherCS, err := Lvl1KeyBuildReply(srcIA, dstIA, &sv, cert111, privateKey112)
			SoMsg("err", err, ShouldBeNil)
			expectedLvl2Key, _ := hex.DecodeString("03666f6fd03e93e69f72993b0e5613283e631017")
			drkeyLvl2.DRKey.Key = expectedLvl2Key

			store.EXPECT().GetLvl2Key(ctx, gomock.Any(), gomock.Any()).Return(nil, nil)
			store.EXPECT().GetLvl1Key(ctx, gomock.Any(), gomock.Any()).Return(nil, nil)
			trustDB.EXPECT().GetChainMaxVersion(gomock.Any(), srcIA).Return(&cert.Chain{Leaf: cert111}, nil)
			msger.EXPECT().RequestDRKeyLvl1(gomock.Any(), gomock.Any(), csSrcAddr, gomock.Any()).Return(replyFromOtherCS, nil)
			store.EXPECT().InsertLvl2Key(ctx, drkeyLvl2).Return(nil)

			reply, err := handler.lvl2KeyBuildReply(ctx, req, srcIA, dstIA, &sv)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply.DRKey", reply.DRKeyRaw, ShouldResemble, common.RawBytes(expectedLvl2Key))
		})
	})
}

func setupHandler(t *testing.T, thisIA addr.IA, confDir string) (*gomock.Controller,
	*mock_infra.MockMessenger, *mock_trustdb.MockTrustDB, *mock_drkeystorage.MockStore,
	*Lvl2ReqHandler) {

	ctrl := gomock.NewController(t)
	msger := mock_infra.NewMockMessenger(ctrl)
	trustDB := mock_trustdb.NewMockTrustDB(ctrl)
	drkeyStore := mock_drkeystorage.NewMockStore(ctrl)
	protocolMap := &protocol.Map{}
	protocolMap.RegisterDefaultProtocol(protocol.StandardImpl)

	handler := &Lvl2ReqHandler{
		State: &config.State{
			TrustDB:    trustDB,
			DRKeyStore: drkeyStore,
		},
		IA:       thisIA,
		Msger:    msger,
		ProtoMap: protocolMap,
	}
	if confDir != "" {
		drkeyStore.EXPECT().SetMasterKey(gomock.Any())
		var err error
		handler.State, err = config.LoadState(confDir, false, trustDB, nil, drkeyStore)
		if err != nil {
			t.Fatalf("Error loading state")
		}
	}
	return ctrl, msger, trustDB, drkeyStore, handler
}
