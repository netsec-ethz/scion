// Copyright 2018 ETH Zurich
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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// EncryptDRKeyLvl1 does the encryption step in the first level key exchange
func EncryptDRKeyLvl1(drkey drkey.Lvl1Key, nonce, pubkey, privkey []byte) ([]byte, error) {
	keyLen := len(drkey.Key)
	msg := make([]byte, addr.IABytes*2+keyLen)
	drkey.SrcIA.Write(msg)
	drkey.DstIA.Write(msg[addr.IABytes:])
	copy(msg[addr.IABytes*2:], drkey.Key)
	cipher, err := scrypto.Encrypt(msg, nonce, pubkey, privkey, scrypto.Curve25519xSalsa20Poly1305)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// DecryptDRKeyLvl1 decrypts the cipher text received during the first level key exchange
func DecryptDRKeyLvl1(cipher, nonce, pubkey, privkey []byte) (drkey.Lvl1Key, error) {
	msg, err := scrypto.Decrypt(cipher, nonce, pubkey, privkey, scrypto.Curve25519xSalsa20Poly1305)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	srcIA := addr.IAFromRaw(msg[:addr.IABytes])
	dstIA := addr.IAFromRaw(msg[addr.IABytes : addr.IABytes*2])
	key := msg[addr.IABytes*2:]
	return drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			SrcIA: srcIA,
			DstIA: dstIA,
		},
		Key: drkey.DRKey(key),
	}, nil
}
