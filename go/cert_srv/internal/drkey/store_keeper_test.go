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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/drkeystorage/mock_drkeystorage"
	"github.com/scionproto/scion/go/lib/periodic"
)

func TestEmptyDB(t *testing.T) {
	Convey("Test empty DB", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		ctrl, store, task := setupStoreKeeper(t)
		defer ctrl.Finish()
		cutoff := uint32(time.Now().Unix())
		tolerance := uint32((5 * time.Minute).Seconds())
		match := func(ctx context.Context, cutoffArg uint32) {
			SoMsg("cutoff", cutoffArg, ShouldBeGreaterThanOrEqualTo, cutoff-1)
			SoMsg("cutoff", cutoffArg, ShouldBeLessThanOrEqualTo, cutoff+tolerance)
		}
		store.EXPECT().RemoveOutdatedLvl1Keys(gomock.Any(), gomock.Any()).Do(match)
		store.EXPECT().RemoveOutdatedLvl2Keys(gomock.Any(), gomock.Any()).Do(match)
		_ = store
		_ = match
		task.Run(ctx)
	})
}

func setupStoreKeeper(t *testing.T) (*gomock.Controller, *mock_drkeystorage.MockStore,
	periodic.Task) {
	ctrl := gomock.NewController(t)
	store := mock_drkeystorage.NewMockStore(ctrl)
	keeper := &StoreKeeper{
		State: &config.State{
			DRKeyStore: store,
		},
	}
	return ctrl, store, keeper
}
