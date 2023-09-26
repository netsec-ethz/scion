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
func DeriveAuthKey(block cipher.Block, resId uint32, bw, in, eg uint16, startTime uint32, resDuration uint16, buffer []byte) []byte {

	if len(buffer) < BufferSize {
		buffer = make([]byte, BufferSize)
	}
	//prepare input
	binary.BigEndian.PutUint32(buffer[0:4], resId<<10|uint32(bw))
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	binary.BigEndian.PutUint32(buffer[8:12], startTime)
	binary.BigEndian.PutUint16(buffer[12:14], resDuration)
	binary.BigEndian.PutUint16(buffer[14:16], 0) //padding

	// should xor input with iv, but we use iv = 0 => identity
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:16]
}

// shifts left a 16 bytes array
func shiftLeft(in []byte) {
	flag := (in[8]&byte(128))>>7 == 1
	binary.BigEndian.PutUint64(in[0:8], binary.BigEndian.Uint64(in[0:8])<<1)
	binary.BigEndian.PutUint64(in[8:16], binary.BigEndian.Uint64(in[8:16])<<1)
	if flag {
		in[7] |= 0x01
	}
}

func xor(a, b []byte) {
	binary.BigEndian.PutUint64(a[0:8], binary.BigEndian.Uint64(a[0:8])^binary.BigEndian.Uint64(b[0:8]))
	binary.BigEndian.PutUint64(a[8:16], binary.BigEndian.Uint64(a[8:16])^binary.BigEndian.Uint64(b[8:16]))
}

// Computes full flyover mac vk
// Needs a xkbuffer of 44 uint32s to store the expanded keys for aes
// dummy buffer is memory used by key expansion to store decryption keys
func FullFlyoverMac(ak []byte, dstIA addr.IA, pktlen uint16, resStartTime uint16, highResTime uint32, buffer []byte, xkbuffer []uint32) []byte {
	if len(buffer) < 32 {
		buffer = make([]byte, 32)
	}
	if len(xkbuffer) < 44 {
		xkbuffer = make([]uint32, 44)
	}

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint16(buffer[10:12], resStartTime)
	binary.BigEndian.PutUint32(buffer[12:16], highResTime)

	expandKeyAsm(10, &ak[0], &xkbuffer[0])
	//compute subkeys
	encryptBlockAsm(10, &xkbuffer[0], &buffer[16], &ZeroBlock[0])

	// Compute K1. Ignore K2 since we will always use K1
	flag1 := buffer[16]&byte(128) == 0
	shiftLeft(buffer[16:32])
	if !flag1 {
		buffer[31] ^= 0x87
	}
	//Compute cmac
	xor(buffer[0:16], buffer[16:32])

	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])

	return buffer[0:16]
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
