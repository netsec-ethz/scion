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

package protocol

import (
	"errors"
	"testing"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
)

type nopProtocol struct {
}

var errorNop = errors.New("Not implemented")

func (n nopProtocol) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	return drkey.Lvl2Key{}, errorNop
}

func TestMap(t *testing.T) {
	m := Map{}
	p := m.DefaultProtocol()
	if p != nil {
		t.Error("Default implementation expected empty")
	}
	lvl2Meta := drkey.Lvl2Meta{
		Protocol: "foo",
		KeyType:  drkey.AS2AS,
	}
	lvl1Key := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(0, 1),
		},
		DRKey: drkey.DRKey{
			Key: common.RawBytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5},
		},
	}
	_, err := m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err == nil {
		t.Error("Expected unable to derive level 2 because no protocol registered")
	}
	m.Register("foo", StandardImpl)
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	lvl2Meta.Protocol = "bar"
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err == nil {
		t.Error("Expected unable to derive level 2 because no protocol registered")
	}
	m.RegisterDefaultProtocol(StandardImpl)
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	nop := nopProtocol{}
	m.Register("bar", nop)
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err != errorNop {
		t.Errorf("Unexpected error: %v", err)
	}
}
