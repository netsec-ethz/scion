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
		lvl2, err := Standard{}.DeriveLvl2(meta, lvl1)
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
		lvl2standard, err := Delegated{}.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 standard failed")
		}
		lvl2deleg, err := Delegated{}.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 delegated failed")
		}
		if !bytes.Equal(lvl2deleg.Key, lvl2standard.Key) {
			t.Fatalf("Keys must be equal for AS2AS")
		}
	}
	protoToLvl2 := map[string]string{
		"foo":  "b4279b032d7d81c38754ab7b253f5ac0",
		"bar":  "a30df8ad348bfce1ecdf1cf83c9e5265",
		"fooo": "434817fb40cb602b36c80e88789aee46",
	}
	for proto, key := range protoToLvl2 {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2Host,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
			DstHost:  addr.HostFromIPStr("127.0.0.1"),
		}
		lvl2, err := Delegated{}.DeriveLvl2(meta, lvl1)
		if err != nil {
			t.Fatalf("Lvl2 failed")
		}
		hexKey := hex.EncodeToString(lvl2.Key)
		if hexKey != key {
			t.Fatalf("Unexpected lvl2 key for protocol [%s]: %s", proto, hexKey)
		}
	}
}

func TestDeriveDelegatedViaDS(t *testing.T) {
	// derive DS and then derive key. Compare to derive directly key
	lvl1Key := getLvl1(t)
	meta := drkey.Lvl2Meta{
		Protocol: "piskes",
		KeyType:  drkey.AS2AS,
		SrcIA:    lvl1Key.SrcIA,
		DstIA:    lvl1Key.DstIA,
		SrcHost:  addr.HostNone{},
		DstHost:  addr.HostNone{},
	}
	lvl2Key, err := piskes{}.DeriveLvl2(meta, lvl1Key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	ds := drkey.DelegationSecret{
		Protocol: lvl2Key.Protocol,
		Epoch:    lvl2Key.Epoch,
		SrcIA:    lvl2Key.SrcIA,
		DstIA:    lvl2Key.DstIA,
		Key:      lvl2Key.Key,
	}
	srcHost := addr.HostFromIPStr("1.1.1.1")
	dstHost := addr.HostFromIPStr("2.2.2.2")
	meta = drkey.Lvl2Meta{
		Protocol: meta.Protocol,
		KeyType:  drkey.Host2Host,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	lvl2KeyViaDS, err := piskes{}.DeriveLvl2FromDS(meta, ds)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_ = lvl2KeyViaDS
	// now get the level 2 key directly without explicitly going through DS
	lvl2Key, err = piskes{}.DeriveLvl2(meta, lvl1Key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !lvl2Key.Equal(lvl2KeyViaDS) {
		t.Fatalf("Level 2 key from DS and direct should be equal. From DS = %s , direct = %s",
			hex.EncodeToString(lvl2KeyViaDS.Key), hex.EncodeToString(lvl2Key.Key))
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

func TestExistingImplementations(t *testing.T) {
	// we test that we have the four implementations we know for now (standard,deleg,scmp,piskes)
	if len(KnownDerivations) != 2 {
		t.Errorf("Wrong number of implementations, expecting 4, got %d", len(KnownDerivations))
	}
	if _, found := KnownDerivations["scmp"]; !found {
		t.Errorf("\"scmp\" implementation not found")
	}
	if _, found := KnownDerivations["piskes"]; !found {
		t.Errorf("\"piskes\" implementation not found")
	}
}
