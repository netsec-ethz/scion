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

func TestSecretValue(t *testing.T) {
	Convey("Initialization", t, func() {
		s := NewStore(nil)
		now := time.Unix(10, 0)
		// no duration or master secret:
		_, err := s.SecretValue(now)
		SoMsg("err", err, ShouldNotBeNil)

		// no master secret yet
		err = s.SetKeyDuration(10 * time.Second)
		SoMsg("err", err, ShouldBeNil)
		_, err = s.SecretValue(now)
		SoMsg("err", err, ShouldNotBeNil)
		// with master secret and duration it should work
		err = s.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		SoMsg("err", err, ShouldBeNil)
		_, err = s.SecretValue(now)
		SoMsg("err", err, ShouldBeNil)
	})

	Convey("Epoch", t, func() {
		s := NewStore(nil)
		now := time.Unix(10, 0)
		s.SetKeyDuration(10 * time.Second)
		s.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		k, _ := s.SecretValue(now)
		SoMsg("begin", k.Epoch.Begin.Unix(), ShouldEqual, 10)
		SoMsg("end", k.Epoch.End.Unix(), ShouldEqual, 20)
	})

	Convey("Key rotation", t, func() {
		s := NewStore(nil)
		now := time.Unix(10, 0)
		s.SetKeyDuration(10 * time.Second)
		s.SetMasterKey(common.RawBytes{0, 1, 2, 3})
		k, _ := s.SecretValue(now)
		savedCurrSV := k
		// advance time 9 seconds
		now = now.Add(9 * time.Second)
		k, _ = s.SecretValue(now)
		SoMsg("return value", k, ShouldEqual, savedCurrSV)
		// advance it so we are in total 10 seconds in the future of the original clock
		now = now.Add(time.Second)
		k, _ = s.SecretValue(now)
		SoMsg("epoch", k.Epoch.Begin, ShouldResemble, savedCurrSV.Epoch.End)
	})
}
