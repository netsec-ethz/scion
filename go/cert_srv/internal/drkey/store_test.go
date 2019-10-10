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
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
)

func TestSecretValueStore(t *testing.T) {
	dur := time.Millisecond
	c := NewSecretValueStore(dur)
	c.timeNowFcn = func() time.Time { return time.Unix(10, 0) }
	_, found := c.Get(1)
	if found {
		t.Fatalf("Should have not been found")
	}
	sv := drkey.SV{SVMeta: drkey.SVMeta{Epoch: drkey.NewEpoch(20, 21)}}
	c.Set(1, sv)
	_, found = c.Get(1)
	if !found {
		t.Fatalf("Should have been found")
	}
	// the ticker should remove the key:
	c.timeNowFcn = func() time.Time { return time.Unix(30, 0) }
	time.Sleep(10 * time.Millisecond)
	_, found = c.Get(1)
	if found {
		t.Fatalf("Should have not been found")
	}

	dur = time.Hour
	c = NewSecretValueStore(dur)
	k1 := drkey.SV{
		SVMeta: drkey.SVMeta{Epoch: drkey.NewEpoch(10, 12)},
		Key:    drkey.DRKey(common.RawBytes{1, 2, 3}),
	}
	c.Set(1, k1)
	k, found := c.Get(1)
	if !found {
		t.Fatalf("Should have been found")
	}
	if !k1.Equal(k) {
		t.Fatalf("Both SVs should be equal. Expected: %v . Got: %v", k1, k)
	}
	if len(c.cache) != 1 {
		t.Fatalf("The cache should contain 1 SV, but it contains %d", len(c.cache))
	}
	time.Sleep(10 * time.Millisecond)
	k2 := drkey.SV{
		SVMeta: drkey.SVMeta{Epoch: drkey.NewEpoch(11, 13)},
		Key:    drkey.DRKey(common.RawBytes{2, 3, 4}),
	}
	c.Set(2, k2)
	if len(c.cache) != 2 {
		t.Fatalf("The cache should contain 2 SVs, but it contains %d", len(c.cache))
	}
	c.timeNowFcn = func() time.Time { return time.Unix(12, 0).Add(-1 * time.Nanosecond) }
	c.cleanExpired()
	if len(c.cache) != 2 {
		t.Fatalf("The cache should contain 2 SVs, but it contains %d", len(c.cache))
	}
	c.timeNowFcn = func() time.Time { return time.Unix(12, 1) }
	c.cleanExpired()
	if len(c.cache) != 1 {
		t.Fatalf("The cache should contain 1 SV, but it contains %d", len(c.cache))
	}
	_, found = c.Get(1)
	if found {
		t.Fatalf("Should have not been found")
	}

}

func TestSecretValueFactory(t *testing.T) {
	master := common.RawBytes{}
	fac := NewSecretValueFactory(master, 10*time.Second)
	_, err := fac.GetSecretValue(time.Now())
	if err == nil {
		t.Fatalf("Should have failed, wrong size of master key")
	}
	master = common.RawBytes{0, 1, 2, 3}
	fac = NewSecretValueFactory(master, 10*time.Second)
	k, err := fac.GetSecretValue(util.SecsToTime(10))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if k.Epoch.Begin.Unix() != 10 {
		t.Fatalf("Wrong Epoch: %v", k.Epoch)
	}
	if k.Epoch.End.Unix() != 20 {
		t.Fatalf("Wrong Epoch: %v", k.Epoch)
	}
	now := time.Unix(10, 0)
	k, _ = fac.GetSecretValue(now)
	savedCurrSV := k
	// advance time 9 seconds
	now = now.Add(9 * time.Second)
	k, _ = fac.GetSecretValue(now)
	if bytes.Compare(k.Key, savedCurrSV.Key) != 0 {
		t.Fatalf("SV should be the same")
	}
	// advance it so we are in total 10 seconds in the future of the original clock
	now = now.Add(time.Second)
	k, _ = fac.GetSecretValue(now)
	if bytes.Compare(k.Key, savedCurrSV.Key) == 0 {
		t.Fatalf("SV should be different")
	}
	if k.Epoch.Begin != savedCurrSV.Epoch.End {
		t.Fatalf("Current key should start when previous one ended (Begin = %v, End = %v)",
			k.Epoch.Begin, savedCurrSV.Epoch.End)
	}
}
func TestDeriveLvl1Key(t *testing.T) {
	srcIA, _ := addr.IAFromString("1-ff00:0:112")
	dstIA, _ := addr.IAFromString("1-ff00:0:111")
	store := ServiceStore{
		localIA:      srcIA,
		secretValues: getSecretValueTestFactory(),
	}
	lvl1Key, err := store.deriveLvl1(dstIA, time.Now())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expectedKey, _ := hex.DecodeString("87ee10bcc9ef1501783949a267f8ec6b")
	if bytes.Compare(lvl1Key.Key, expectedKey) != 0 {
		t.Fatalf("Bad level 1 derivation. Expected: %s ; Got: %s",
			hex.EncodeToString(expectedKey), hex.EncodeToString(lvl1Key.Key))
	}
}

func TestLvl1KeyBuildReply(t *testing.T) {
	srcIA, _ := addr.IAFromString("1-ff00:0:112")
	dstIA, _ := addr.IAFromString("1-ff00:0:111")
	cert111, privateKey111, cert112, privateKey112 := loadCertsKeys(t)

	store := ServiceStore{
		localIA:      srcIA,
		secretValues: getSecretValueTestFactory(),
		asDecryptKey: privateKey112,
	}
	handler := &lvl1ReqHandler{
		request: nil,
		store:   &store,
	}
	lvl1Key, err := store.deriveLvl1(dstIA, time.Now())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	reply, err := handler.buildReply(lvl1Key, cert111)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	retrievedLvl1Key, err := getLvl1KeyFromReply(&reply, srcIA, cert112, privateKey111)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if bytes.Compare(retrievedLvl1Key.Key, lvl1Key.Key) != 0 {
		t.Fatalf("Bad level 1 reply. Expected: %s ; Got: %s",
			hex.EncodeToString(lvl1Key.Key), hex.EncodeToString(retrievedLvl1Key.Key))
	}
	if !retrievedLvl1Key.Equal(lvl1Key) {
		t.Fatalf("Different keys. Expected: %v ; Got: %v", lvl1Key, retrievedLvl1Key)
	}
}

func TestDeriveLvl2Key(t *testing.T) {
	srcIA, _ := addr.IAFromString("1-ff00:0:1")
	dstIA, _ := addr.IAFromString("1-ff00:0:2")
	handler := lvl2ReqHandler{}

	sv, err := getSecretValueTestFactory().GetSecretValue(util.SecsToTime(0))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	k, _ := hex.DecodeString("c584cad32613547c64823c756651b6f5") // just a level 1 key
	lvl1Key := drkey.Lvl1Key{
		Key: k,
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: sv.Epoch,
			SrcIA: srcIA,
			DstIA: dstIA,
		},
	}
	var srcHost addr.HostAddr = addr.HostNone{}
	var dstHost addr.HostAddr = addr.HostNone{}
	meta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "scmp",
		Epoch:    lvl1Key.Epoch,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	lvl2Key, err := handler.deriveLvl2(meta, lvl1Key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expectedKey, _ := hex.DecodeString("b90ceff1586e5b5cc3313445df18f271")
	if bytes.Compare(lvl2Key.Key, expectedKey) != 0 {
		t.Fatalf("Bad level 2 derivation. Expected: %s ; Got: %s",
			hex.EncodeToString(expectedKey), hex.EncodeToString(lvl2Key.Key))
	}
}
