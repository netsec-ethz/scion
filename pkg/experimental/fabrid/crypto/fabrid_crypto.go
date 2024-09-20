// Copyright 2024 ETH Zurich
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

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	ext "github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
)

const FabridMacInputSize int = 46

//	MAC input:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Identifier (8B)                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Cons Ingress (2B)        |  Cons Egress (2B)        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |ePolicyID(1B)|sHostLen(1B)| SrcHostAddr (4-16 B)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func computeFabridHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer []byte,
	key []byte, ingress uint16, egress uint16) error {
	if len(key) != 16 {
		return serrors.New("Wrong key length", "expected", 16, "actual", len(key))
	}
	if len(tmpBuffer) < FabridMacInputSize {
		return serrors.New("tmpBuffer too small", "expected",
			FabridMacInputSize, "actual", len(tmpBuffer))
	}
	if len(resultBuffer) < 16 {
		return serrors.New("resultBuffer too small", "expected",
			16, "actual", len(resultBuffer))
	}

	if err := id.Serialize(tmpBuffer[0:8]); err != nil {
		return err
	}
	srcAddr := s.RawSrcAddr
	requiredLen := 14 + len(srcAddr)
	binary.BigEndian.PutUint16(tmpBuffer[8:10], ingress)
	binary.BigEndian.PutUint16(tmpBuffer[10:12], egress)
	tmpBuffer[12] = f.EncryptedPolicyID
	tmpBuffer[13] = byte(s.SrcAddrType.Length())
	copy(tmpBuffer[14:requiredLen], srcAddr)

	if err := macBlock(key, tmpBuffer[30:46], tmpBuffer[:requiredLen],
		resultBuffer[:]); err != nil {
		return err
	}
	return nil
}

// Computes and sets the base HVF for the provided FABRID Hopfield
func ComputeBaseHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[0:3])
	return nil
}

// Computes and sets the verified HVF for the provided FABRID Hopfield
func ComputeVerifiedHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

// VerifyAndUpdate recomputes the FABRID HVF and verifies that the provided HVF
// matches the base HVF. In that case it overwrites the provided HVF with the verified HVF.
func VerifyAndUpdate(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	if !bytes.Equal(computedHVF[:3], f.HopValidationField[:]) {
		return serrors.New("HVF is not valid")
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func calcPolicyEncryptionMask(key []byte, id *ext.IdentifierOption) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, aes.BlockSize)
	if err = id.Serialize(buf); err != nil {
		return nil, err
	}
	cipher.Encrypt(buf, buf)
	return buf, nil
}

// ComputePolicyID acts as a decryptor for an encrypted FABRID policy index.
func ComputePolicyID(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	key []byte) (fabrid.PolicyID, error) {

	buf, err := calcPolicyEncryptionMask(key, id)
	if err != nil {
		return 0, err
	}
	return fabrid.PolicyID(f.EncryptedPolicyID ^ buf[0]), nil
}

// EncryptPolicyID encrypts a FABRID policy index.
func EncryptPolicyID(f fabrid.PolicyID, id *ext.IdentifierOption,
	key []byte) (uint8, error) {

	buf, err := calcPolicyEncryptionMask(key, id)
	if err != nil {
		return 0, err
	}
	return uint8(f) ^ buf[0], nil
}

// VerifyPathValidator recomputes the path validator from the updated HVFs and compares it
// with the path validator in the packet. Returns the secret 5th byte of the computed validator.
// `tmpBuffer` requires at least (numHops*3 rounded up to next multiple of 16) + 16 bytes
func VerifyPathValidator(f *ext.FabridOption, tmpBuffer []byte, pathKey []byte) (uint8, error) {
	inputLength := 3 * len(f.HopfieldMetadata)
	requiredBufferLength := 16 + (inputLength+15)&^15
	if len(tmpBuffer) < requiredBufferLength {
		return 0, serrors.New("tmpBuffer length is invalid", "expected",
			requiredBufferLength,
			"actual", len(tmpBuffer))
	}
	for i, meta := range f.HopfieldMetadata {
		copy(tmpBuffer[16+i*3:16+(i+1)*3], meta.HopValidationField[:3])
	}
	err := macBlock(pathKey, tmpBuffer[:16], tmpBuffer[16:16+inputLength], tmpBuffer[16:])
	if err != nil {
		return 0, err
	}
	validationNumber := tmpBuffer[20]
	if !bytes.Equal(tmpBuffer[16:20], f.PathValidator[:]) {
		return validationNumber, serrors.New("Path validator is not valid",
			"validator", base64.StdEncoding.EncodeToString(f.PathValidator[:]),
			"computed", base64.StdEncoding.EncodeToString(tmpBuffer[16:20]))
	}
	return validationNumber, nil
}

// InitValidators sets all HVFs of the FABRID option and computes the
// path validator.
func InitValidators(f *ext.FabridOption, id *ext.IdentifierOption, s *slayers.SCION,
	tmpBuffer []byte, pathKey *drkey.FabridKey, asHostKeys map[addr.IA]*drkey.FabridKey,
	asAsKeys map[addr.IA]*drkey.FabridKey, hops []snet.HopInterface) error {

	outBuffer := make([]byte, 16)
	var pathValInputLength int
	var pathValBuffer []byte
	if pathKey != nil {
		pathValInputLength = 3 * len(f.HopfieldMetadata)
		pathValBuffer = make([]byte, (pathValInputLength+15)&^15)
	}
	for i, meta := range f.HopfieldMetadata {
		if meta.FabridEnabled {
			var key *drkey.FabridKey
			var found bool
			if meta.ASLevelKey {
				key, found = asAsKeys[hops[i].IA]
			} else {
				key, found = asHostKeys[hops[i].IA]
			}
			if !found {
				return serrors.New("InitValidators expected AS to AS key but was not in"+
					" dictionary", "AS", hops[i].IA)
			}

			err := computeFabridHVF(meta, id, s, tmpBuffer, outBuffer, key.Key[:],
				uint16(hops[i].IgIf), uint16(hops[i].EgIf))
			if err != nil {
				return err
			}
			outBuffer[0] &= 0x3f // ignore first two (left) bits
			outBuffer[3] &= 0x3f // ignore first two (left) bits
			copy(meta.HopValidationField[:3], outBuffer[:3])
			if pathKey != nil {
				copy(pathValBuffer[i*3:(i+1)*3], outBuffer[3:6])
			}
		}
	}
	if pathKey != nil {
		err := macBlock(pathKey.Key[:], tmpBuffer[:16], pathValBuffer[:pathValInputLength],
			pathValBuffer)
		if err != nil {
			return err
		}
		copy(f.PathValidator[:4], pathValBuffer[:4])
	}
	return nil
}

var zeroBlock [16]byte

func macBlock(key []byte, tmp []byte, src []byte, dst []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return serrors.WrapStr("unable to initialize AES cipher", err)
	}
	if len(dst) < 16 {
		return serrors.New("Dst length is invalid", "expected", 16, "actual", len(dst))
	}
	if len(src) == 0 {
		return serrors.New("Src length cannot be 0")
	}
	if len(tmp) < 16 {
		return serrors.New("tmp length is invalid", "expected", 16, "actual", len(tmp))
	}
	encryptor := cipher.NewCBCEncrypter(block, zeroBlock[:])
	paddingLength := (16 - len(src)%16) % 16
	blockCount := len(src) / block.BlockSize()

	if blockCount != 0 {
		encryptor.CryptBlocks(dst, src[:16*blockCount])
	}
	if paddingLength != 0 {
		copy(tmp, src[16*blockCount:])
		copy(tmp[16-paddingLength:], zeroBlock[:paddingLength])
		encryptor.CryptBlocks(dst, tmp)
	}
	return nil
}
