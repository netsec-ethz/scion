//go:build amd64 || arm64 || ppc64 || ppc64le

package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
)

// defined in asm_* assembly files

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//TODO: test expandKeyAsm on arm64 and ppc64 machines. Compare with code in go/src/crypto/aes/asm_* if necessary

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32)

const BufferSize = 16

var ZeroBlock [aes.BlockSize]byte

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv), where sv is this AS' secret value
func DeriveAuthKey(block cipher.Block, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

	if len(buffer) < BufferSize {
		buffer = make([]byte, BufferSize)
	}
	//prepare input
	copy(buffer[0:4], resID_bw)
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	copy(buffer[8:12], times)
	binary.BigEndian.PutUint32(buffer[12:16], 0) //padding

	// should xor input with iv, but we use iv = 0 => identity
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:16], nil
}

// shifts left a 16 bytes array
func shiftLeft(in []byte) {
	flag := (in[8] & byte(128+64)) >> 6
	binary.BigEndian.PutUint64(in[0:8], binary.BigEndian.Uint64(in[0:8])<<2+uint64(flag))
	binary.BigEndian.PutUint64(in[8:16], binary.BigEndian.Uint64(in[8:16])<<2)
}

func xor(a, b []byte) {
	binary.BigEndian.PutUint64(a[0:8], binary.BigEndian.Uint64(a[0:8])^binary.BigEndian.Uint64(b[0:8]))
	binary.BigEndian.PutUint64(a[8:16], binary.BigEndian.Uint64(a[8:16])^binary.BigEndian.Uint64(b[8:16]))
}

// Computes full flyover mac vk
// Needs a xkbuffer of 44 uint32s to store the expanded keys for aes
// dummy buffer is memory used by key expansion to store decryption keys
// TODO: remove usage of dummy buffer; is no longer used for AMD64 machines and should (not tested) be fine for arm64 machines as well
func FullFlyoverMac(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte, xkbuffer []uint32) ([]byte, error) {
	if len(buffer) < 34 {
		buffer = make([]byte, 34)
	}
	if len(xkbuffer) < 44 {
		xkbuffer = make([]uint32, 44)
	}

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint32(buffer[10:14], baseTime)
	binary.BigEndian.PutUint32(buffer[14:18], highResTime)

	expandKeyAsm(10, &ak[0], &xkbuffer[0])
	//compute subkeys
	encryptBlockAsm(10, &xkbuffer[0], &buffer[18], &ZeroBlock[0])

	// Compute K2. Ignore K1 since we will always use K2
	flag1 := buffer[18]&byte(128) == 0
	flag2 := buffer[18]&byte(64) == 0
	shiftLeft(buffer[18:34])
	if !flag1 {
		buffer[32] ^= 0x01
		buffer[33] ^= 0x0e
	}
	if !flag2 {
		buffer[33] ^= 0x87
	}
	//Compute cmac
	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])

	buffer[0] ^= buffer[16]
	buffer[1] ^= buffer[17]
	xor(buffer[0:16], buffer[18:34])
	buffer[2] ^= 0x80

	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])
	//TODO: return only first 28 bits (4 bytes, set last 4 to zero)
	return buffer[0:16], nil
}

// Compares two 16 byte arrays.
// Always returns false if at least one input has a length different from 16
// Returns true if equal, false otherwise
func CompareAk(a []byte, b []byte) bool {
	if len(a) != 16 || len(b) != 16 {
		return false
	}
	return binary.BigEndian.Uint64(a[0:8]) == binary.BigEndian.Uint64(b[0:8]) && binary.BigEndian.Uint64(a[8:16]) == binary.BigEndian.Uint64(b[8:16])
}

// around 800 ns

// Compares two 4 byte arrays.
// Always returns false if at least one input is of a different length.
// Returns true if equal, false otherwise.
// Expects 4 bits of padding to also be identical.
func CompareVk(a, b []byte) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	return binary.BigEndian.Uint32(a) == binary.BigEndian.Uint32(b)
}

// around 1.2 microseconds

// Compare two 4 byte arrays, ignores last 4 bits.
// Always returns false if at least one input is of a different length.
// Returns true if equal, false otherwise.
func CompareVkPadded(a, b []byte) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3]&0xf0 == b[3]&0xf0
}
