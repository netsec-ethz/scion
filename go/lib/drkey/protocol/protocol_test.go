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
	"encoding/hex"
	"errors"
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
)

func TestDerive(t *testing.T) {
	master0 := common.RawBytes{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	epoch := drkey.NewEpoch(0, 1)
	srcIA, _ := addr.IAFromString("1-ff00:0:111")
	dstIA, _ := addr.IAFromString("1-ff00:0:112")
	sv, err := drkey.DeriveSV(drkey.SVMeta{
		Epoch: epoch,
	}, master0)
	if err != nil {
		t.Fatalf("SV failed")
	}
	if hex.EncodeToString(sv.Key) != "0f6f810ca0b7f33f3f4e975196e0acc2" {
		t.Fatalf("Unexpected key: %s", hex.EncodeToString(sv.Key))
	}
	lvl1, err := DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}, sv)
	if err != nil {
		t.Fatalf("Lvl1 failed")
	}
	if hex.EncodeToString(lvl1.Key) != "dd05f7d9fd85a3ff5597b41723e67499" {
		t.Fatalf("Unexpected key: %s", hex.EncodeToString(lvl1.Key))
	}

	protoToKey := map[string]string{
		"foo":  "a992befcb7ec02cfc7ba69e7bfce2f02",
		"bar":  "97f051b6d9cce55a599ef54440668b52",
		"fooo": "62b9b381c6f556ee2b1c1b2d3c68a14e",
	}
	for proto, key := range protoToKey {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2AS,
			SrcIA:    srcIA,
			DstIA:    dstIA,
		}
		lvl2, err := standardImpl.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 failed")
		}
		hexKey := hex.EncodeToString(lvl2.Key)
		if hexKey != key {
			t.Fatalf("Wrong key: %s", hexKey)
		}
	}
}

type nopProtocol struct{}

var errorNop = errors.New("Not implemented")

func (n nopProtocol) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	return drkey.Lvl2Key{}, errorNop
}

func (n nopProtocol) Name() string {
	return "nop"
}

func TestRegistry(t *testing.T) {
	m := NewRegistry()
	lvl2Meta := drkey.Lvl2Meta{
		Protocol: "foo",
		KeyType:  drkey.AS2AS,
	}
	lvl1Key := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(0, 1),
		},
		Key: drkey.DRKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5},
	}
	_, err := m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err == nil {
		t.Error("Expected unable to derive level 2 because no protocol registered")
	}
	m.Register("foo", StandardName)
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	nop := &nopProtocol{}
	KnownDerivations[nop.Name()] = nop
	defer func() {
		delete(KnownDerivations, nop.Name())
	}()
	m.Register("bar", "nop")
	lvl2Meta.Protocol = "bar"
	_, err = m.DeriveLvl2(lvl2Meta, lvl1Key)
	if err != errorNop {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestExistingImplementations(t *testing.T) {
	// we test that we have the four implementations we know for now (standard,deleg,scmp,piskes)
	if len(KnownDerivations) != 4 {
		t.Errorf("Wrong number of implementations, expecting 4, got %d", len(KnownDerivations))
	}
	if _, found := KnownDerivations[StandardName]; !found {
		t.Errorf("\"%s\" implementation not found", StandardName)
	}
	if _, found := KnownDerivations[DelegatedName]; !found {
		t.Errorf("\"%s\" implementation not found", DelegatedName)
	}
	if _, found := KnownDerivations["scmp"]; !found {
		t.Errorf("\"scmp\" implementation not found")
	}
	if _, found := KnownDerivations["piskes"]; !found {
		t.Errorf("\"piskes\" implementation not found")
	}
}
