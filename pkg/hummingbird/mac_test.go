package hummingbird_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/stretchr/testify/require"
)

// Example verified with https://cryptii.com/pipes/aes-encryption
func TestDeriveAuthKey(t *testing.T) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	resID_bw := []byte{0, 1, 2, 3}
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	startend := []byte{0, 1, 2, 3}
	expected := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	//8e 13 91 77 4c 02 e4 12 86 6f 74 2d c8 ac 71 db   a9 5a eb 01 10 5e b2 6d a2 7a 83 66 43 81 99 4f
	//TODO: check 32 bytes buffer key result

	key, err := hummingbird.DeriveAuthKey(sv, resID_bw, in, eg, startend, buffer)

	require.Equal(t, expected, key)
	require.NoError(t, err)

}

// verified with https://artjomb.github.io/cryptojs-extension/

func TestFlyOverMac(t *testing.T) {
	ak := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var baseTs uint32 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 18)
	expected := []byte{106, 137, 42, 100, 162, 8, 148, 176, 96, 188, 243, 236, 179, 195, 218, 185}
	//expected with 0, 23, 1234, 4321: 726f7d9e 17e3cbe1 d47a32eb d8a5e26e
	mac, err := hummingbird.FullMac(ak, dstIA, pktlen, baseTs, highResTs, buffer)
	fmt.Print(mac)
	require.Equal(t, expected, mac)
	require.NoError(t, err)

	//in: 000000000000000017000004d2000010e1
	//key: 8e 13 91 77 4c 02 e4 12 86 6f 74 2d c8 ac 71 db
	// works for that, but not once we add dstIA...
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

func TestMeasureCompareAk(t *testing.T) {
	a := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	b := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 218}
	res := true
	start := time.Now()
	for i := 0; i < 1000; i++ {
		res = hummingbird.CompareAk(a, b)
	}
	elapsed := time.Since(start)
	fmt.Print(elapsed)
	require.False(t, res)
}

// 480 ns
func TestIntCompare(t *testing.T) {
	var a uint64 = 128732
	var b uint64 = 1287323
	var c uint64 = 672964
	var d uint64 = 672964
	res := true
	start := time.Now()
	for i := 0; i < 1000; i++ {
		res = CompareInt(a, b, c, d)
	}
	elapsed := time.Since(start)
	fmt.Print(elapsed)
	require.False(t, res)
}

// lower bound for 16 bytes comparison
func CompareInt(a, b, c, d uint64) bool {
	return a == b && c == d
}

func TestCompareVk(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{2, 2, 3, 4}
	d := []byte{1, 2, 3, 6}

	require.True(t, hummingbird.CompareVk(a, b))
	require.False(t, hummingbird.CompareVk(a, c))
	require.False(t, hummingbird.CompareVk(a, d))
}

func TestMeasureCompareVk(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 4, 4}
	res := true
	start := time.Now()
	for i := 0; i < 1000; i++ {
		res = hummingbird.CompareVk(a, b)
	}
	elapsed := time.Since(start)
	fmt.Print(elapsed)
	require.False(t, res)
}
