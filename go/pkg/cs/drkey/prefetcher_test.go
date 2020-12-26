// Copyright 2021 ETH Zurich
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

package drkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
	cs_drkey "github.com/scionproto/scion/go/pkg/cs/drkey"
	"github.com/scionproto/scion/go/pkg/cs/drkey/mock_drkey"
)

func TestPrefetcherRun(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	mock_engine := mock_drkey.NewMockServiceEngine(mctrl)

	prefetcher := cs_drkey.Prefetcher{
		Engine:      mock_engine,
		LocalIA:     xtest.MustParseIA("1-ff00:0:110"),
		KeyDuration: time.Hour,
	}

	firstCached := mock_engine.EXPECT().GetLvl1PrefetchInfo().Times(1).Return(nil)

	cachedKeys := []cs_drkey.Lvl1PrefetchInfo{
		{
			IA:    xtest.MustParseIA("1-ff00:0:112"),
			Proto: drkey.DNS,
		},
	}
	secondCached := mock_engine.EXPECT().GetLvl1PrefetchInfo().After(
		firstCached).Times(1).Return(cachedKeys)

	cachedKeys = append(cachedKeys, cs_drkey.Lvl1PrefetchInfo{
		IA:    xtest.MustParseIA("1-ff00:0:111"),
		Proto: drkey.DNS,
	})
	mock_engine.EXPECT().GetLvl1PrefetchInfo().After(
		secondCached).Times(1).Return(cachedKeys)

	mock_engine.EXPECT().GetLvl1Key(gomock.Any(), gomock.Any()).Times(3)

	prefetcher.Run(context.Background())
	prefetcher.Run(context.Background())
	prefetcher.Run(context.Background())

}
