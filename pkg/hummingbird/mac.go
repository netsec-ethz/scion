package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/addr"
)

const BufferSize = 16
const Mask byte = 240

var ZeroBlock [aes.BlockSize]byte

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv), where sv is this AS' secret value
func DeriveAuthKey(block cipher.Block, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

	// around 200 microseconds for 1000 iterations
	if len(buffer) < BufferSize {
		buffer = make([]byte, BufferSize)
	}

	//prepare input
	copy(buffer[0:4], resID_bw)
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	copy(buffer[8:12], times)
	binary.BigEndian.PutUint32(buffer[12:16], 0) //padding

	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	mode.CryptBlocks(buffer, buffer)

	return buffer, nil
}

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv), where sv is this AS' secret value
func DeriveAuthKeySelfmade(block cipher.Block, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

	//around 30 microseconds
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
	// iv makes no sense to use as we encrypt only one block
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:16], nil
}

func FullMac(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {
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

func FullMacSelfmade(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {
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
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3]&Mask == b[3]&Mask
}
