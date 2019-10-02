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

package drkey

// import (
// 	"context"
// 	"testing"
// 	"time"

// 	"github.com/golang/mock/gomock"
// 	. "github.com/smartystreets/goconvey/convey"

// 	"github.com/scionproto/scion/go/cert_srv/internal/config"
// 	"github.com/scionproto/scion/go/lib/addr"
// 	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
// 	"github.com/scionproto/scion/go/lib/drkeystorage/mock_drkeystorage"
// 	"github.com/scionproto/scion/go/lib/infra/mock_infra"
// 	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/mock_trustdb"
// 	"github.com/scionproto/scion/go/lib/scrypto/cert"
// 	"github.com/scionproto/scion/go/lib/xtest/matchers"
// )

// func TestUnionSet(t *testing.T) {
// 	Convey("Union", t, func() {
// TODO(juagargi) use xtest.MustParseIA
// 		a := asSet{
// 			ia("1-ff00:0:111"): struct{}{},
// 		}
// 		b := asSet{}
// 		un := unionSet(a, b)
// 		SoMsg("union", un, ShouldResemble, a)
// 		un = unionSet(un, a)
// 		SoMsg("union", un, ShouldResemble, a)
// 		b = asSet{
// 			ia("1-ff00:0:112"): struct{}{},
// 		}
// 		un = unionSet(a, b)
// 		SoMsg("union", len(un), ShouldEqual, 2)
// 		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:111"))
// 		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:112"))
// 		for i := range a {
// 			delete(a, i)
// 		}
// 		for i := range b {
// 			delete(b, i)
// 		}
// 		SoMsg("union", len(un), ShouldEqual, 2)
// 		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:111"))
// 		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:112"))
// 	})
// 	Convey("Difference", t, func() {
// 		a := asSet{
// 			ia("1-ff00:0:111"): struct{}{},
// 			ia("1-ff00:0:112"): struct{}{},
// 		}
// 		b := asSet{
// 			ia("1-ff00:0:111"): struct{}{},
// 		}
// 		expected := asSet{
// 			ia("1-ff00:0:112"): struct{}{},
// 		}
// 		diff := differenceSet(a, b)
// 		SoMsg("difference", diff, ShouldResemble, expected)
// 		diff = differenceSet(a, asSet{})
// 		SoMsg("difference", diff, ShouldResemble, a)
// 		diff = differenceSet(asSet{}, a)
// 		SoMsg("difference", diff, ShouldResemble, asSet{})
// 	})
// }

// func TestUpdatePending(t *testing.T) {
// 	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
// 	defer cancelF()
// 	Convey("From changes in DB", t, func() {
// 		ctrl, _, _, store, requester := setupRequester(t)
// 		defer ctrl.Finish()

// 		SoMsg("pending ASes", len(requester.PendingASes.set), ShouldEqual, 0)
// 		asList := []addr.IA{
// 			ia("1-ff00:0:111"),
// 			ia("1-ff00:0:112"),
// 			ia("1-ff00:0:113"),
// 		}
// 		validAsList := []addr.IA{
// 			ia("1-ff00:0:112"),
// 		}
// 		store.EXPECT().GetLvl1SrcASes(gomock.Any()).Return(asList, nil)
// 		store.EXPECT().GetValidLvl1SrcASes(gomock.Any(), gomock.Any()).Return(validAsList, nil).Do(
// 			func(ctx context.Context, argValidTime uint32) {
// 				now := uint32(time.Now().Unix())
// 				SoMsg("validTime", argValidTime, ShouldBeGreaterThanOrEqualTo, now)
// 				// 60 is how far in the future the key has to be valid
// 				SoMsg("validTime", argValidTime, ShouldBeLessThanOrEqualTo, now+uint32(60))
// 			})
// 		err := requester.UpdatePendingList(ctx)
// 		SoMsg("err", err, ShouldBeNil)
// 		asList = []addr.IA{
// 			ia("1-ff00:0:113"),
// 		}
// 		SoMsg("pending ASes", requester.PendingASes.set, ShouldResemble, setFromList(asList))
// 	})
// }

// func TestProcessPending(t *testing.T) {
// 	ctx, cancelF := context.WithTimeout(context.Background(), time.Millisecond)
// 	defer cancelF()
// 	Convey("Replies are on time", t, func() {
// 		// TODO(juagargi): if we move the logic of processing the reply to the reply handler only, remove half of this test
// 		ctrl, msger, trustDB, store, requester := setupRequester(t)
// 		defer ctrl.Finish()

// 		sv := getTestSV()
// 		pending := []addr.IA{
// 			ia("1-ff00:0:112"),
// 			ia("1-ff00:0:113"),
// 		}
// 		requester.PendingASes.set = setFromList(pending)
// 		_, privateKey111, cert112, _ := loadCertsKeys(t)
// 		// use the same cert for both ASes (simplifies test):
// 		trustDB.EXPECT().GetChainMaxVersion(gomock.Any(), gomock.Any()).Return(&cert.Chain{Leaf: cert112}, nil).Times(2)
// 		newReply := func(srcIA addr.IA) *drkey_mgmt.DRKeyLvl1Rep {
// 			dstIA := ia("1-ff00:0:111")
// 			replyTo111, err := lvl1KeyBuildReply(srcIA, dstIA, &sv, cert112, privateKey111)
// 			if err != nil {
// 				panic("Logic error")
// 			}
// 			return replyTo111
// 		}
// 		// both replies are encrypted using the same cert:
// 		msger.EXPECT().RequestDRKeyLvl1(gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(
// 			pending[0]), gomock.Any()).Return(newReply(pending[0]), nil)
// 		msger.EXPECT().RequestDRKeyLvl1(gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(
// 			pending[1]), gomock.Any()).Return(newReply(pending[1]), nil)
// 		store.EXPECT().InsertLvl1Key(gomock.Any(), gomock.Any()).Times(2)
// 		err := requester.ProcessPendingList(ctx)
// 		SoMsg("err", err, ShouldBeNil)
// 		_ = store
// 	})
// 	Convey("On reply takes forever but doesn't block the rest", t, func() {
// 		// TODO(juagargi): better if we don't have to do this but rely on the L1 handler
// 	})
// }

// // setupRequester prepares the requester for ff00:0:111
// func setupRequester(t *testing.T) (*gomock.Controller, *mock_infra.MockMessenger,
// 	*mock_trustdb.MockTrustDB, *mock_drkeystorage.MockStore, *Requester) {
// 	ctrl := gomock.NewController(t)
// 	msger := mock_infra.NewMockMessenger(ctrl)
// 	trustDB := mock_trustdb.NewMockTrustDB(ctrl)
// 	drkeyStore := mock_drkeystorage.NewMockStore(ctrl)
// 	requester := &Requester{
// 		Msgr: msger,
// 		IA:   ia("1-ff00:0:111"),
// 	}
// 	drkeyStore.EXPECT().SetMasterKey(gomock.Any())
// 	var err error
// 	requester.State, err = config.LoadState("testdata/as111/", false, trustDB, nil, drkeyStore)
// 	if err != nil {
// 		t.Fatalf("Error loading state")
// 	}
// 	return ctrl, msger, trustDB, drkeyStore, requester
// }
