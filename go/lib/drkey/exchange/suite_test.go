// Copyright 2020 ETH Zurich
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

package exchange

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSuiteDRKeyLvl1(t *testing.T) {
	lvl1 := genLvl1Key(t)
	sndPubKey, sndPrivKey, err := scrypto.GenKeyPair(scrypto.Curve25519xSalsa20Poly1305)
	require.NoError(t, err)
	rcvPubKey, rcvPrivKey, err := scrypto.GenKeyPair(scrypto.Curve25519xSalsa20Poly1305)
	require.NoError(t, err)
	nonce, err := scrypto.Nonce(24)
	require.NoError(t, err)
	cipherMsg, err := EncryptDRKeyLvl1(lvl1, nonce, rcvPubKey, sndPrivKey)
	require.NoError(t, err)
	gotLvl1, err := DecryptDRKeyLvl1(cipherMsg, nonce, sndPubKey, rcvPrivKey)
	require.NoError(t, err)

	assert.Equal(t, lvl1.Lvl1Meta.SrcIA, gotLvl1.Lvl1Meta.SrcIA)
	assert.Equal(t, lvl1.Lvl1Meta.DstIA, gotLvl1.Lvl1Meta.DstIA)
	assert.Equal(t, lvl1.Key, gotLvl1.Key)
}

func genLvl1Key(t *testing.T) drkey.Lvl1Key {
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
	require.Equal(t, []byte(sv.Key), svTgtKey)
	lvlTgtKey := xtest.MustParseHexString("51663adbc06e55f40a9ad899cf0775e5")
	lvl1, err := protocol.DeriveLvl1(drkey.Lvl1Meta{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}, sv)
	require.NoError(t, err)
	require.Equal(t, []byte(lvl1.Key), lvlTgtKey)

	return lvl1
}
