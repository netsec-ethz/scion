package hummingbird_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
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
	binary.BigEndian.PutUint16(expected[0:2], in)
	binary.BigEndian.PutUint16(expected[2:4], eg)
	binary.BigEndian.PutUint32(expected[4:8], resId<<10)
	expected[6] |= byte(bw >> 8)
	expected[7] = byte(bw)
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

// Golden Data test used for cross verification with other implementations
func TestDeriveAuthKeyGoldenData(t *testing.T) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	expected := [16]byte{0x25, 0xe6, 0xb9, 0x75, 0x96, 0x7, 0x3, 0x93, 0xef, 0x54, 0x73, 0x67,
		0x1b, 0xf6, 0x3a, 0x9a}

	// Run DeriveAuthKey Function
	block, err := aes.NewCipher(sv)
	if err != nil {
		require.Fail(t, err.Error())
	}

	key := hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected[:], key)

	key = hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected[:], key)
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
// Does not take into account the process of moving data into the buffer
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

// We use CBC-MAC using aes for the flyover mac.
func TestFlyoverMac(t *testing.T) {
	ak := []byte{0x7e, 0x61, 0x4, 0x91, 0x30, 0x6b, 0x95, 0xec, 0xb5, 0x75, 0xc6, 0xe9,
		0x4c, 0x5a, 0x89, 0x84}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 32)
	xkbuffer := make([]uint32, 44)

	// Compute expected output based on library cbc-mac implementation
	expected := make([]byte, 16)
	binary.BigEndian.PutUint64(expected[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(expected[8:10], pktlen)
	binary.BigEndian.PutUint16(expected[10:12], resStartTs)
	binary.BigEndian.PutUint32(expected[12:16], highResTs)
	block, err := aes.NewCipher(ak)
	if err != nil {
		require.Fail(t, err.Error())
	}
	block.Encrypt(expected[:], expected[:])

	mac := hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
	mac = hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
}

// Golden data test used for cross verification with other implementations
func TestFlyoverMacGoldenData(t *testing.T) {
	ak := []byte{0x7e, 0x61, 0x4, 0x91, 0x30, 0x6b, 0x95, 0xec, 0xb5, 0x75, 0xc6, 0xe9,
		0x4c, 0x5a, 0x89, 0x84}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 32)
	xkbuffer := make([]uint32, 44)

	expected := [16]byte{0xbe, 0xad, 0xcf, 0x70, 0xf, 0x75, 0xdf, 0x8, 0xde, 0x91, 0xe9, 0xda,
		0xf5, 0xcb, 0x9f, 0x74}

	mac := hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected[:], mac)
	mac = hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected[:], mac)
}

func BenchmarkFlyoverMac(b *testing.B) {
	ak := []byte{0x7e, 0x61, 0x4, 0x91, 0x30, 0x6b, 0x95, 0xec, 0xb5, 0x75, 0xc6, 0xe9,
		0x4c, 0x5a, 0x89, 0x84}
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

// Benchmark of the FLyover Mac if we use library code only
// Without using the assembly code in the asm_* files
func BenchmarkFlyoverMacLib(b *testing.B) {
	ak := []byte{0x7e, 0x61, 0x4, 0x91, 0x30, 0x6b, 0x95, 0xec, 0xb5, 0x75, 0xc6, 0xe9,
		0x4c, 0x5a, 0x89, 0x84}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 16)

	b.ResetTimer()
	// Compute expected output based on library cbc-mac implementation
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
		binary.BigEndian.PutUint16(buffer[8:10], pktlen)
		binary.BigEndian.PutUint16(buffer[10:12], resStartTs)
		binary.BigEndian.PutUint32(buffer[12:16], highResTs)
		block, err := aes.NewCipher(ak)
		if err != nil {
			require.Fail(b, err.Error())
		}
		block.Encrypt(buffer[:], buffer[:])
	}
}
