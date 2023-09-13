package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/dchest/cmac"
)

const BufferSize = 16
const Mask byte = 240

func DeriveAuthKey(sv []byte, resID_bw []byte, in uint16, eg uint16, times []byte, buffer []byte) ([]byte, error) {

	if len(buffer) < BufferSize {
		buffer = make([]byte, BufferSize)
	}

	//prepare input
	copy(buffer[0:4], resID_bw)
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	copy(buffer[8:12], times)
	binary.BigEndian.PutUint16(buffer[12:16], 0) //padding

	block, err := aes.NewCipher(sv)
	if err != nil {
		return nil, err
	}
	var ZeroBlock [aes.BlockSize]byte //TODO: experiment where to best declare this
	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])

	mode.CryptBlocks(buffer, buffer) //TODO: put into separate variable?

	return buffer, nil
}

func FullMac(ak []byte, dstIA uint64, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {
	if len(buffer) < 18 {
		buffer = make([]byte, 18)
	}

	binary.BigEndian.PutUint64(buffer[0:8], dstIA)
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

// Compares two 16 byte arrays.
// Returns true if equal, false otherwise
func CompareAk(a []byte, b []byte) bool {
	if len(a) != 16 || len(b) != 16 {
		return false
	}
	return binary.BigEndian.Uint64(a[0:8]) == binary.BigEndian.Uint64(b[0:8]) && binary.BigEndian.Uint64(a[8:16]) == binary.BigEndian.Uint64(b[8:16])
}

// around 800 ns

// Compares two 4 byte arrays
// Returns true if equal, false otherwise
// expects 4 bytes of padding to also be identical
func CompareVk(a, b []byte) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	return binary.BigEndian.Uint32(a) == binary.BigEndian.Uint32(b)
}

// around 1.2 microseconds

// Compare two 4 byte arrays, ignores last 4 bits
// Returns true if equal, false otherwise
func CompareVkPadded(a, b []byte) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3]&Mask == b[3]&Mask
}
