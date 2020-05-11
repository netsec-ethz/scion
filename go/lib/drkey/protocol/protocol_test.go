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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDeriveStandard(t *testing.T) {
	lvl1 := getLvl1(t)
	protoToKey := map[string][]byte{
		"foo":  xtest.MustParseHexString("def3aa32ce47d4374469148b5c04fac5"),
		"bar":  xtest.MustParseHexString("8ada021cabf2b14765f468f3c8995edb"),
		"fooo": xtest.MustParseHexString("7f8e507aecf38c09e4cb10a0ff0cc497"),
	}

	for proto, key := range protoToKey {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2AS,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
		}
		lvl2, err := Standard{}.DeriveLvl2(meta, lvl1)
		require.NoError(t, err)
		assert.EqualValues(t, key, lvl2.Key)
	}

	dstHost := addr.HostFromIPStr("127.0.0.1")
	protoToKey = map[string][]byte{
		"foo":  xtest.MustParseHexString("84e628f7c9318d6831ff4f85827f7af3"),
		"bar":  xtest.MustParseHexString("f51fa0769a6e3d2b9570eefb788a92c0"),
		"fooo": xtest.MustParseHexString("d88513be2ff73b11615053540146e960"),
	}
	for proto, key := range protoToKey {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.AS2Host,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
			DstHost:  dstHost,
		}
		lvl2, err := Standard{}.DeriveLvl2(meta, lvl1)
		require.NoError(t, err)
		assert.EqualValues(t, key, lvl2.Key)
	}

	srcHost := addr.HostFromIPStr("127.0.0.2")
	protoToKey = map[string][]byte{
		"foo":  xtest.MustParseHexString("3ca3190844028277e05ebfaf3c2dd3b0"),
		"bar":  xtest.MustParseHexString("b0bc9ccbd6ca923bdfbad7d1ad358960"),
		"fooo": xtest.MustParseHexString("5635ad5283cfe080e2c8e99e6c3306af"),
	}
	for proto, key := range protoToKey {
		meta := drkey.Lvl2Meta{
			Protocol: proto,
			KeyType:  drkey.Host2Host,
			SrcIA:    lvl1.SrcIA,
			DstIA:    lvl1.DstIA,
			SrcHost:  srcHost,
			DstHost:  dstHost,
		}
		lvl2, err := Standard{}.DeriveLvl2(meta, lvl1)
		require.NoError(t, err)
		assert.EqualValues(t, key, lvl2.Key)
	}
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
		lvl2standard, err := Standard{}.DeriveLvl2(meta, lvl1)
		require.NoError(t, err)
		lvl2deleg, err := Delegated{}.DeriveLvl2(meta, lvl1)
		require.NoError(t, err)
		assert.Equal(t, lvl2standard.Key, lvl2deleg.Key)
	}

	protoToLvl2 := map[string][]byte{
		"foo":  xtest.MustParseHexString("b4279b032d7d81c38754ab7b253f5ac0"),
		"bar":  xtest.MustParseHexString("a30df8ad348bfce1ecdf1cf83c9e5265"),
		"fooo": xtest.MustParseHexString("434817fb40cb602b36c80e88789aee46"),
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
		require.NoError(t, err)
		assert.EqualValues(t, key, lvl2.Key)
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	_ = lvl2KeyViaDS
	// now get the level 2 key directly without explicitly going through DS
	lvl2Key, err = piskes{}.DeriveLvl2(meta, lvl1Key)
	require.NoError(t, err)
	assert.Equal(t, lvl2Key, lvl2KeyViaDS)
}

func getLvl1(t *testing.T) drkey.Lvl1Key {
	meta := drkey.SVMeta{
		Epoch: drkey.NewEpoch(0, 1),
	}
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	svTgtKey := xtest.MustParseHexString("47bfbb7d94706dc9e79825e5a837b006")
	epoch := drkey.NewEpoch(0, 1)
	srcIA, _ := addr.IAFromString("1-ff00:0:111")
	dstIA, _ := addr.IAFromString("1-ff00:0:112")
	sv, err := drkey.DeriveSV(meta, asSecret)
	require.NoError(t, err)
	require.EqualValues(t, svTgtKey, sv.Key)

	lvlTgtKey := xtest.MustParseHexString("51663adbc06e55f40a9ad899cf0775e5")
	lvl1, err := DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}, sv)
	require.NoError(t, err)
	require.EqualValues(t, lvlTgtKey, lvl1.Key)

	return lvl1
}

func TestExistingImplementations(t *testing.T) {
	// we test that we have the four implementations we know for now (standard,deleg,scmp,piskes)
	require.Len(t, KnownDerivations, 2)
	require.Contains(t, KnownDerivations, "scmp")
	require.Contains(t, KnownDerivations, "piskes")
}
