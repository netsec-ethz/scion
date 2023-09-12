package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/addr"
)

const BufferSize = 16

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

func FullMac(ak []byte, dstIA addr.IA, pktlen uint16, baseTime uint32, highResTime uint32, buffer []byte) ([]byte, error) {

	if len(buffer) < 144 {
		buffer = make([]byte, 144)
	}

	binary.BigEndian.PutUint64(buffer[0:64], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[64:80], pktlen)
	binary.BigEndian.PutUint32(buffer[80:112], baseTime)
	binary.BigEndian.PutUint32(buffer[112:144], highResTime)

	block, err := aes.NewCipher(ak)
	if err != nil {
		return []byte{}, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return []byte{}, err
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
