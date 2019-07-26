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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

func TestNew(t *testing.T) {
	Convey("Initialize and ticker", t, func() {
		dur := time.Millisecond
		c := NewEpochToSV(dur)
		c.timeNowFcn = func() time.Time { return time.Unix(10, 0) }
		_, found := c.Get(1)
		SoMsg("found", found, ShouldBeFalse)
		c.Set(1, &SV{SVMeta: SVMeta{Epoch: NewEpoch(20, 21)}})
		_, found = c.Get(1)
		SoMsg("found", found, ShouldBeTrue)
		// the ticker should remove the key:
		c.timeNowFcn = func() time.Time { return time.Unix(30, 0) }
		time.Sleep(10 * time.Millisecond)
		_, found = c.Get(1)
		SoMsg("found", found, ShouldBeFalse)
	})

	Convey("Key overlaps", t, func() {
		dur := time.Hour
		c := NewEpochToSV(dur)
		k1 := &SV{
			SVMeta: SVMeta{Epoch: NewEpoch(10, 12)},
			DRKey:  DRKey{common.RawBytes{1, 2, 3}},
		}
		// k1 := &DRKey{Epoch: *NewEpoch(10, 12), Key: common.RawBytes{1, 2, 3}}
		c.Set(1, k1)
		k, found := c.Get(1)
		SoMsg("found", found, ShouldBeTrue)
		SoMsg("retrieved", *k, ShouldResemble, *k1)
		SoMsg("contained", len(c.cache), ShouldEqual, 1)
		time.Sleep(10 * time.Millisecond)
		k2 := &SV{
			SVMeta: SVMeta{Epoch: NewEpoch(11, 13)},
			DRKey:  DRKey{common.RawBytes{2, 3, 4}},
		}
		// k2 := &DRKey{Epoch: *NewEpoch(11, 13), Key: common.RawBytes{2, 3, 4}}
		c.Set(2, k2)
		SoMsg("contained", len(c.cache), ShouldEqual, 2)
		c.timeNowFcn = func() time.Time { return time.Unix(12, 0).Add(-1 * time.Nanosecond) }
		c.cleanExpired()
		SoMsg("contained", len(c.cache), ShouldEqual, 2)
		c.timeNowFcn = func() time.Time { return time.Unix(12, 1) }
		c.cleanExpired()
		SoMsg("contained", len(c.cache), ShouldEqual, 1)
		_, found = c.Get(1)
		SoMsg("found", found, ShouldBeFalse)
	})
}
