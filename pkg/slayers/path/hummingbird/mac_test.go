package hummingbird_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/stretchr/testify/require"
)

func TestDeriveAuthKey(t *testing.T) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	block, err := aes.NewCipher(sv)
	if err != nil {
		require.Fail(t, err.Error())
	}

	// Compute expected result with library CBC
	expected := make([]byte, 16)
	binary.BigEndian.PutUint32(expected[0:4], resId<<10)
	expected[2] |= byte(bw >> 8)
	expected[3] = byte(bw)
	binary.BigEndian.PutUint16(expected[4:6], in)
	binary.BigEndian.PutUint16(expected[6:8], eg)
	binary.BigEndian.PutUint32(expected[8:12], start)
	binary.BigEndian.PutUint16(expected[12:14], duration)
	binary.BigEndian.PutUint16(expected[14:16], 0)

	var ZeroBlock [aes.BlockSize]byte
	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	mode.CryptBlocks(expected, expected)

	// Run DeriveAuthKey Function
	block, err = aes.NewCipher(sv)
	if err != nil {
		require.Fail(t, err.Error())
	}

	key := hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected, key)

	key = hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected, key)
}

func BenchmarkDeriveAuthKey(b *testing.B) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}

	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	block, err := aes.NewCipher(sv)
	if err != nil {
		require.Fail(b, err.Error())
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	}
}

// BenchmarkDeriveAuthKeyManually benchmarks obtaining Ak by just using the stdlib.
// Results in my machine of 5.987 ns/op.
func BenchmarkDeriveAuthKeyManually(b *testing.B) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	var in uint16 = 2
	var eg uint16 = 5
	var start uint16 = 0x0001
	var end uint16 = 0x0203

	src := make([]byte, hummingbird.AkBufferSize)
	binary.BigEndian.PutUint32(src[0:4], resId<<10)
	src[2] |= byte(bw >> 8)
	src[3] = byte(bw)
	binary.BigEndian.PutUint16(src[4:6], in)
	binary.BigEndian.PutUint16(src[6:8], eg)
	binary.BigEndian.PutUint16(src[8:10], start)
	binary.BigEndian.PutUint16(src[10:12], end)
	binary.BigEndian.PutUint32(src[12:16], 0) //padding

	buffer := make([]byte, 16)
	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block.Encrypt(buffer[:], src)
	}
}

// verified with https://artjomb.github.io/cryptojs-extension/

func TestFlyOverMac(t *testing.T) {
	ak := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 32)
	xkbuffer := make([]uint32, 44)

	// Compute expected output based on library cmac implementation
	expected := make([]byte, 16)
	binary.BigEndian.PutUint64(expected[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(expected[8:10], pktlen)
	binary.BigEndian.PutUint16(expected[10:12], resStartTs)
	binary.BigEndian.PutUint32(expected[12:16], highResTs)

	block, err := aes.NewCipher(ak)
	if err != nil {
		require.Fail(t, err.Error())
	}
	c, err := cmac.New(block)
	if err != nil {
		require.Fail(t, err.Error())
	}
	if _, err := c.Write(expected[0:16]); err != nil {
		require.Fail(t, err.Error())
	}

	expected = c.Sum(expected[:0])

	//expected with 0, 23, 1234, 4321: 726f7d9e 17e3cbe1 d47a32eb d8a5e26e
	mac := hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
	mac = hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
}

func BenchmarkFlyoverMac(b *testing.B) {
	ak := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 32)
	xkbuffer := make([]uint32, 44)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	}
}

func TestCompareAk(t *testing.T) {
	a := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	b := []byte{142, 19, 145, 151, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	c := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 218}
	d := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}

	require.True(t, hummingbird.CompareAk(a, d))
	require.False(t, hummingbird.CompareAk(a, b))
	require.False(t, hummingbird.CompareAk(a, c))
}

func BenchmarkCompareAk(b *testing.B) {
	a := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	c := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 218}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hummingbird.CompareAk(a, c)
	}
}

func TestCompareVk(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5, 6}
	b := []byte{1, 2, 3, 4, 5, 6}
	c := []byte{2, 2, 3, 4, 5, 6}
	d := []byte{1, 2, 3, 6, 5, 6}

	require.True(t, hummingbird.CompareVk(a, b))
	require.False(t, hummingbird.CompareVk(a, c))
	require.False(t, hummingbird.CompareVk(a, d))
}

func BenchmarkCompareVk(b *testing.B) {
	a := []byte{1, 2, 3, 4, 5, 6}
	c := []byte{1, 2, 4, 4, 5, 6}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hummingbird.CompareVk(a, c)
	}
}

func BenchmarkSubtleCompare(b *testing.B) {
	a := []byte{1, 2, 3, 4, 5, 6}
	c := []byte{1, 2, 4, 4, 5, 6}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hummingbird.SubtleCompare(a, c)
	}
}
