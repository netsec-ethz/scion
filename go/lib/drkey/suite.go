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

package drkey

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	drkeySalt   = "Derive DRKey Key" // same as in Python
	drkeyLength = 16
)

// SetKey creates the SV_A . The passed asSecret is typically the AS master password
func (sv *DRKeySV) SetKey(asSecret common.RawBytes, epoch Epoch) error {
	msLen := len(asSecret)
	all := make(common.RawBytes, msLen+8)
	_, err := asSecret.WritePld(all[:msLen])
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(all[msLen:], epoch.Begin)
	binary.LittleEndian.PutUint32(all[msLen+4:], epoch.End)
	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	sv.Key = key
	return nil
}

func (k *DRKeyLvl1) SetKey(secret common.RawBytes) error {
	mac, err := scrypto.InitMac(secret)
	if err != nil {
		return err
	}
	all := make(common.RawBytes, addr.IABytes)
	k.DstIA.Write(all)
	mac.Write(all)
	tmp := make([]byte, 0, mac.Size())
	k.Key = mac.Sum(tmp)
	return nil
}

func (k *DRKeyLvl2) SetKey(secret common.RawBytes) error {
	h, err := scrypto.InitMac(secret)
	if err != nil {
		return err
	}
	p := []byte(k.Protocol)
	pLen := len(p)
	inputLen := 1 + pLen
	switch k.KeyType {
	case AS2AS:
		break
	case AS2Host:
		it, err := InputTypeFromHostTypes(k.DstHost.Type(), addr.HostTypeNone)
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	case Host2Host:
		it, err := InputTypeFromHostTypes(k.SrcHost.Type(), k.DstHost.Type())
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	default:
		return common.NewBasicError("Unknown DRKey type", nil)
	}
	all := make(common.RawBytes, inputLen)
	copy(all[:1], common.RawBytes{uint8(pLen)})
	copy(all[1:], p)
	switch k.KeyType {
	case AS2AS:
		break
	case AS2Host:
		copy(all[pLen+1:], k.DstHost.Pack())
	case Host2Host:
		copy(all[pLen+1:], k.SrcHost.Pack())
		copy(all[pLen+1+k.SrcHost.Size():], k.DstHost.Pack())
	default:
		return common.NewBasicError("Unknown DRKey type", nil)
	}
	k.Key = h.Sum(all)
	return nil
}

// EncryptDRKeyLvl1 does the encryption step in the first level key exchange
func EncryptDRKeyLvl1(drkey *DRKeyLvl1, nonce, pubkey, privkey common.RawBytes) (common.RawBytes, error) {
	keyLen := len(drkey.Key)
	msg := make(common.RawBytes, addr.IABytes*2+keyLen)
	drkey.SrcIA.Write(msg)
	drkey.DstIA.Write(msg[addr.IABytes:])
	drkey.Key.WritePld(msg[addr.IABytes*2:])
	cipher, err := scrypto.Encrypt(msg, nonce, pubkey, privkey, scrypto.Curve25519xSalsa20Poly1305)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// DecryptDRKeyLvl1 decrypts the cipher text received during the first level key exchange
func DecryptDRKeyLvl1(cipher, nonce, pubkey, privkey common.RawBytes) (*DRKeyLvl1, error) {
	msg, err := scrypto.Decrypt(cipher, nonce, pubkey, privkey, scrypto.Curve25519xSalsa20Poly1305)
	if err != nil {
		return nil, err
	}
	srcIA := addr.IAFromRaw(msg[:addr.IABytes])
	dstIA := addr.IAFromRaw(msg[addr.IABytes : addr.IABytes*2])
	key := msg[addr.IABytes*2:]
	return NewDRKeyLvl1(Epoch{}, key, srcIA, dstIA), nil
}
