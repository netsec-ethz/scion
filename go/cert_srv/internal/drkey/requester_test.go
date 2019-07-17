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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

func ia(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic("Unexpected bad IA")
	}
	return ia
}

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
	//
}
