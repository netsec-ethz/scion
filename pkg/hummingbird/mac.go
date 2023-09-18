//go:build amd64 || arm64 || ppc64 || ppc64le

package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/addr"
)

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

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
	//If we want a 256 bits key: set buffer[16:32] to zero

	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	mode.CryptBlocks(buffer, buffer)

	return buffer, nil
}

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv), where sv is this AS' secret value
func DeriveAuthKeySelfmade(block cipher.Block, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

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

func DeriveAuthKeySelfmade256(block cipher.Block, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

	//around 30 microseconds
	if len(buffer) < 32 {
		buffer = make([]byte, 32)
	}
	//prepare input
	copy(buffer[0:4], resID_bw)
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	copy(buffer[8:12], times)
	binary.BigEndian.PutUint32(buffer[12:16], 0) //padding

	// should xor input with iv, but we use iv = 0 => identity
	// iv makes no sense to use as we encrypt only one block
	block.Encrypt(buffer[0:16], buffer[0:16])

	//second block is all 0 padding, xor is unnecessary
	block.Encrypt(buffer[16:32], buffer[0:16])
	return buffer[0:32], nil
}

func FlyoverMac(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {
	if len(buffer) < 18 {
		buffer = make([]byte, 18)
	}
	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint32(buffer[10:14], baseTime)
	binary.BigEndian.PutUint32(buffer[14:18], highResTime)

	block, err := aes.NewCipher(ak)
	if err != nil {
		return []byte{}, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return []byte{}, err
	}
	if _, err := mac.Write(buffer[0:18]); err != nil {
		panic(err)
	}
	return mac.Sum(buffer[:0]), nil
}

// shifts left a 16 bytes array
func shiftLeft(in []byte) {
	flag := (in[8] & byte(128)) >> 7
	binary.BigEndian.PutUint64(in[0:8], binary.BigEndian.Uint64(in[0:8])<<1+uint64(flag))
	binary.BigEndian.PutUint64(in[8:16], binary.BigEndian.Uint64(in[8:16])<<1)
}

func xor(a, b []byte) {
	binary.BigEndian.PutUint64(a[0:8], binary.BigEndian.Uint64(a[0:8])^binary.BigEndian.Uint64(b[0:8]))
	binary.BigEndian.PutUint64(a[8:16], binary.BigEndian.Uint64(a[8:16])^binary.BigEndian.Uint64(b[8:16]))
}

// Computes flyover mac Vk
// Rewrites cmac algorithm instead of calling cmac library in order to not do a make() call
func FlyoverMacSelfmade(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {
	if len(buffer) < 34 {
		buffer = make([]byte, 34)
	}

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint32(buffer[10:14], baseTime)
	binary.BigEndian.PutUint32(buffer[14:18], highResTime)

	block, err := aes.NewCipher(ak) //not optimal, performs make() call which may put data on heap
	if err != nil {
		return []byte{}, err
	}
	//compute subkeys
	block.Encrypt(buffer[18:34], ZeroBlock[:])
	// compute K1
	flag := buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	// compute K2, overwrite K1 since we will always use K2
	flag = buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	//Compute cmac
	block.Encrypt(buffer[0:16], buffer[0:16])

	buffer[0] ^= buffer[16]
	buffer[1] ^= buffer[17]
	xor(buffer[0:16], buffer[18:34])
	buffer[2] ^= 0x80

	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:16], nil
}

// Computes flyover mac vk
// Needs a xkbuffer of 44 uint32s to store the expanded keys for aes
// This method does not include a make() call like aes.NewCipher, but also does not use the fast aes implementations that the crypto library uses
// As a result, this method has a similar performance to FlyoverMacSelfmade
func FlyoverMacSelfmadeAes(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte, xkbuffer []uint32) ([]byte, error) {
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

	aesExpandKey128(xkbuffer, ak)
	//compute subkeys
	aesEncrypt(xkbuffer, buffer[18:34], ZeroBlock[:])

	// compute K1
	// TODO: combine shifts for K1 and K2 into one shift << 2
	flag := buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	// compute K2, overwrite K1 since we will always use K2
	flag = buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	//Compute cmac
	aesEncrypt(xkbuffer, buffer[0:16], buffer[0:16])

	buffer[0] ^= buffer[16]
	buffer[1] ^= buffer[17]
	xor(buffer[0:16], buffer[18:34])
	buffer[2] ^= 0x80

	aesEncrypt(xkbuffer, buffer[0:16], buffer[0:16])
	return buffer[0:16], nil
}

// Computes flyover mac vk
// Needs a xkbuffer of 44 uint32s to store the expanded keys for aes
// This method does not include a make() call like aes.NewCipher, but also does not use the fast aes implementations that the crypto library uses
// As a result, this method has a similar performance to FlyoverMacSelfmade
func FlyoverMacAssembly(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte, xkbuffer, dummy []uint32) ([]byte, error) {
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

	expandKeyAsm(10, &ak[0], &xkbuffer[0], &dummy[0])
	//aesExpandKey128(xkbuffer, ak)
	//compute subkeys
	encryptBlockAsm(10, &xkbuffer[0], &buffer[18], &ZeroBlock[0])
	//aesEncrypt(xkbuffer, buffer[18:34], ZeroBlock[:])

	// compute K1
	// TODO: combine shifts for K1 and K2 into one shift << 2
	flag := buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	// compute K2, overwrite K1 since we will always use K2
	flag = buffer[18]&byte(128) == 0
	shiftLeft(buffer[18:34])
	if !flag {
		buffer[33] ^= 0x87
	}
	//Compute cmac
	//aesEncrypt(xkbuffer, buffer[0:16], buffer[0:16])
	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])

	buffer[0] ^= buffer[16]
	buffer[1] ^= buffer[17]
	xor(buffer[0:16], buffer[18:34])
	buffer[2] ^= 0x80

	//aesEncrypt(xkbuffer, buffer[0:16], buffer[0:16])
	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])
	return buffer[0:16], nil
}

// Compares two 16 byte arrays.
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

// code based on crypto/aes/block.go
func aesExpandKey128(xk []uint32, key []byte) {

	// Nk = 4, Nr = 10
	for i := 0; i < 4; i++ {
		xk[i] = binary.BigEndian.Uint32(key[4*i : 4*(i+1)])
	}

	// 44 = 4 * (Nr + 1), 4 is block size
	for i := 4; i < 44; i++ {
		t := xk[i-1]
		if i&0x3 == 0 {
			t = subw(t<<8|t>>24) ^ (uint32(powx[i>>2-1]) << 24)
		}
		// used if we want to change to 192 or 256 bits keys
		// else if nk > 6 && i%nk == 4 {
		// 	t = subw(t)
		// }
		xk[i] = xk[i-4] ^ t
	}
}

// code based on crypto/aes/block.go
func aesExpandKey256(xk []uint32, key []byte) {

	// Nk = 8, Nr = 10
	for i := 0; i < 8; i++ {
		xk[i] = binary.BigEndian.Uint32(key[4*i : 4*(i+1)])
	}

	// 44 = 4 * (Nr + 1), 4 is block size
	for i := 8; i < 60; i++ {
		t := xk[i-1]
		if i&0x7 == 0 {
			t = subw(t<<8|t>>24) ^ (uint32(powx[i>>3-1]) << 24)
		} else if i%8 == 4 {
			t = subw(t)
		}
		xk[i] = xk[i-4] ^ t
	}
}

func subw(w uint32) uint32 {
	return uint32(sbox0[w>>24])<<24 |
		uint32(sbox0[w>>16&0xff])<<16 |
		uint32(sbox0[w>>8&0xff])<<8 |
		uint32(sbox0[w&0xff])
}

func aesEncrypt(xk []uint32, dst, src []byte) {

	//Copy pasted from crypto/aes/block.go
	_ = src[15] // early bounds check
	s0 := binary.BigEndian.Uint32(src[0:4])
	s1 := binary.BigEndian.Uint32(src[4:8])
	s2 := binary.BigEndian.Uint32(src[8:12])
	s3 := binary.BigEndian.Uint32(src[12:16])

	// First round just XORs input with key.
	s0 ^= xk[0]
	s1 ^= xk[1]
	s2 ^= xk[2]
	s3 ^= xk[3]

	// Middle rounds shuffle using tables.
	// Number of rounds is set by length of expanded key.
	//nr := len(xk)/4 - 2 // - 2: one above, one more below //8
	nr := 9
	k := 4
	var t0, t1, t2, t3 uint32
	for r := 0; r < nr; r++ {
		t0 = xk[k+0] ^ te0[uint8(s0>>24)] ^ te1[uint8(s1>>16)] ^ te2[uint8(s2>>8)] ^ te3[uint8(s3)]
		t1 = xk[k+1] ^ te0[uint8(s1>>24)] ^ te1[uint8(s2>>16)] ^ te2[uint8(s3>>8)] ^ te3[uint8(s0)]
		t2 = xk[k+2] ^ te0[uint8(s2>>24)] ^ te1[uint8(s3>>16)] ^ te2[uint8(s0>>8)] ^ te3[uint8(s1)]
		t3 = xk[k+3] ^ te0[uint8(s3>>24)] ^ te1[uint8(s0>>16)] ^ te2[uint8(s1>>8)] ^ te3[uint8(s2)]
		k += 4
		s0, s1, s2, s3 = t0, t1, t2, t3
	}

	// Last round uses s-box directly and XORs to produce output.
	s0 = uint32(sbox0[t0>>24])<<24 | uint32(sbox0[t1>>16&0xff])<<16 | uint32(sbox0[t2>>8&0xff])<<8 | uint32(sbox0[t3&0xff])
	s1 = uint32(sbox0[t1>>24])<<24 | uint32(sbox0[t2>>16&0xff])<<16 | uint32(sbox0[t3>>8&0xff])<<8 | uint32(sbox0[t0&0xff])
	s2 = uint32(sbox0[t2>>24])<<24 | uint32(sbox0[t3>>16&0xff])<<16 | uint32(sbox0[t0>>8&0xff])<<8 | uint32(sbox0[t1&0xff])
	s3 = uint32(sbox0[t3>>24])<<24 | uint32(sbox0[t0>>16&0xff])<<16 | uint32(sbox0[t1>>8&0xff])<<8 | uint32(sbox0[t2&0xff])

	s0 ^= xk[k+0]
	s1 ^= xk[k+1]
	s2 ^= xk[k+2]
	s3 ^= xk[k+3]

	_ = dst[15] // early bounds check
	binary.BigEndian.PutUint32(dst[0:4], s0)
	binary.BigEndian.PutUint32(dst[4:8], s1)
	binary.BigEndian.PutUint32(dst[8:12], s2)
	binary.BigEndian.PutUint32(dst[12:16], s3)
}
