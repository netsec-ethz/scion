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
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
)

func TestDeriveStandard(t *testing.T) {
	lvl1 := getLvl1(t)
	protoToKey := map[string]string{
		"foo":  "def3aa32ce47d4374469148b5c04fac5",
		"bar":  "8ada021cabf2b14765f468f3c8995edb",
		"fooo": "7f8e507aecf38c09e4cb10a0ff0cc497",
	}
	for proto, key := range protoToKey {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2AS,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
		}
		lvl2, err := standardImpl.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 failed")
		}
		hexKey := hex.EncodeToString(lvl2.Key)
		if hexKey != key {
			t.Fatalf("Unexpected lvl2 key for protocol [%s]: %s", proto, hexKey)
		}
	}
	// TODO(juagargi): test as2host and host2host. Get the key values from an authorative source.
}

func TestDeriveDelegated(t *testing.T) {
	lvl1 := getLvl1(t)
	for _, proto := range []string{"foo", "bar", "fooo"} {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2AS,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
		}
		lvl2standard, err := delegatedImpl.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 standard failed")
		}
		lvl2deleg, err := delegatedImpl.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 delegated failed")
		}
		if !bytes.Equal(lvl2deleg.Key, lvl2standard.Key) {
			t.Fatalf("Keys must be equal for AS2AS")
		}
	}
	protoToLvl2 := map[string]string{
		"foo":  "84e628f7c9318d6831ff4f85827f7af3",
		"bar":  "f51fa0769a6e3d2b9570eefb788a92c0",
		"fooo": "d88513be2ff73b11615053540146e960",
	}
	for proto, key := range protoToLvl2 {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2Host,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
			DstHost:  addr.HostFromIPStr("127.0.0.1"),
		}
		lvl2, err := delegatedImpl.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 failed")
		}
		hexKey := hex.EncodeToString(lvl2.Key)
		if hexKey != key {
			t.Fatalf("Unexpected lvl2 key for protocol [%s]: %s", proto, hexKey)
		}
	}
}

func getLvl1(t *testing.T) drkey.Lvl1Key {
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
	if hex.EncodeToString(sv.Key) != "47bfbb7d94706dc9e79825e5a837b006" {
		t.Fatalf("Unexpected sv: %s", hex.EncodeToString(sv.Key))
	}
	lvl1, err := DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}, sv)
	if err != nil {
		t.Fatalf("Lvl1 failed")
	}
	if hex.EncodeToString(lvl1.Key) != "51663adbc06e55f40a9ad899cf0775e5" {
		t.Fatalf("Unexpected lvl1 key: %s", hex.EncodeToString(lvl1.Key))
	}
	return lvl1
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
