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

package test

import (
	"encoding/binary"
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
)

type KeyMap map[fastSlow]drkey.Lvl2Key

type fastSlow struct {
	fast addr.IA
	slow addr.IA
}

func GetKey(keyMap KeyMap, fastIA, slowIA addr.IA) (drkey.Lvl2Key, bool) {
	k, ok := keyMap[fastSlow{fast: fastIA, slow: slowIA}]
	return k, ok
}

func MockKeys1SlowSide(t *testing.T, slowIA string, fastIAs ...string) KeyMap {
	return mockKeysManyFast(t, drkey.AS2AS, slowIA, addr.HostNone{}, fastIAs...)
}

func MockKeys1SlowSideWithHost(t *testing.T, slowIA, slowHost string,
	fastIAs ...string) KeyMap {

	sHost := addr.HostFromIP(xtest.MustParseIP(t, slowHost))
	return mockKeysManyFast(t, drkey.AS2Host, slowIA, sHost, fastIAs...)
}

func mockKeysManyFast(t *testing.T, keyType drkey.Lvl2KeyType, slowIA string, sHost addr.HostAddr,
	fastIAs ...string) KeyMap {

	t.Helper()
	sIA := xtest.MustParseIA(slowIA)
	m := make(KeyMap)
	for _, fast := range fastIAs {
		fIA := xtest.MustParseIA(fast)
		m[fastSlow{fast: fIA, slow: sIA}] = mockKey(keyType, fIA, sIA, sHost)
	}
	return m
}

func mockKey(keyType drkey.Lvl2KeyType, fast, slow addr.IA, slowhost addr.HostAddr) drkey.Lvl2Key {
	k := xtest.MustParseHexString("0123456789abcdef0123456789abcdef") // 16 bytes
	binary.BigEndian.PutUint64(k[:8], uint64(fast))
	binary.BigEndian.PutUint64(k[8:], uint64(slow))
	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  keyType,
			Protocol: "colibri",
			Epoch:    drkey.NewEpoch(0, 100),
			SrcIA:    fast,
			DstIA:    slow,
			DstHost:  slowhost,
		},
		Key: k,
	}
}
