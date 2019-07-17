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

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey/keystore/mock_keystore"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
)

func TestUnionSet(t *testing.T) {
	Convey("Union", t, func() {
		a := asSet{
			ia("1-ff00:0:111"): struct{}{},
		}
		b := asSet{}
		un := unionSet(a, b)
		SoMsg("union", un, ShouldResemble, a)
		un = unionSet(un, a)
		SoMsg("union", un, ShouldResemble, a)
		b = asSet{
			ia("1-ff00:0:112"): struct{}{},
		}
		un = unionSet(a, b)
		SoMsg("union", len(un), ShouldEqual, 2)
		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:111"))
		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:112"))
		for i := range a {
			delete(a, i)
		}
		for i := range b {
			delete(b, i)
		}
		SoMsg("union", len(un), ShouldEqual, 2)
		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:111"))
		SoMsg("union", un, ShouldContainKey, ia("1-ff00:0:112"))
	})
	Convey("Difference", t, func() {
		a := asSet{
			ia("1-ff00:0:111"): struct{}{},
			ia("1-ff00:0:112"): struct{}{},
		}
		b := asSet{
			ia("1-ff00:0:111"): struct{}{},
		}
		expected := asSet{
			ia("1-ff00:0:112"): struct{}{},
		}
		diff := unionDifference(a, b)
		SoMsg("difference", diff, ShouldResemble, expected)
		diff = unionDifference(a, asSet{})
		SoMsg("difference", diff, ShouldResemble, a)
		diff = unionDifference(asSet{}, a)
		SoMsg("difference", diff, ShouldResemble, asSet{})
	})
}

func TestUpdatePending(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	Convey("From changes in DB", t, func() {
		ctrl, _, store, requester := setupRequester(t)
		defer ctrl.Finish()

		SoMsg("pending ASes", len(requester.PendingASes.set), ShouldEqual, 0)
		asList := []addr.IA{
			ia("1-ff00:0:111"),
			ia("1-ff00:0:112"),
			ia("1-ff00:0:113"),
		}
		validAsList := []addr.IA{
			ia("1-ff00:0:111"),
		}
		store.EXPECT().GetL1SrcASes(gomock.Any()).Return(asList, nil)
		store.EXPECT().GetValidL1SrcASes(gomock.Any(), gomock.Any()).Return(validAsList, nil).Do(
			func(ctx context.Context, argValidTime uint32) {
				now := uint32(time.Now().Unix())
				SoMsg("validTime", argValidTime, ShouldBeGreaterThanOrEqualTo, now)
				// 60 is how far in the future the key has to be valid
				SoMsg("validTime", argValidTime, ShouldBeLessThanOrEqualTo, now+uint32(60))
			})
		err := requester.UpdatePendingList(ctx)
		SoMsg("err", err, ShouldBeNil)
		asList = []addr.IA{
			ia("1-ff00:0:112"),
			ia("1-ff00:0:113"),
		}
		SoMsg("pending ASes", requester.PendingASes.set, ShouldResemble, setFromList(asList))
	})
}

func ia(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic("Unexpected bad IA")
	}
	return ia
}

func setupRequester(t *testing.T) (*gomock.Controller, *mock_infra.MockMessenger, *mock_keystore.MockDRKeyStore, *Requester) {
	ctrl := gomock.NewController(t)
	msger := mock_infra.NewMockMessenger(ctrl)
	drkeyStore := mock_keystore.NewMockDRKeyStore(ctrl)
	requester := &Requester{
		State: &config.State{
			DRKeyStore: drkeyStore,
		},
	}
	return ctrl, msger, drkeyStore, requester
}
