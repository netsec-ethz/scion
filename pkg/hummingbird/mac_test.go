package hummingbird_test

import (
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/stretchr/testify/require"
)

func TestDeriveAuthKey(t *testing.T) {
	sv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	resID_bw := []byte{0, 1, 2, 3}
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	startend := []byte{0, 1, 2, 3}
	expected := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}

	key, err := hummingbird.DeriveAuthKey(sv, resID_bw, in, eg, startend, buffer)

	require.Equal(t, key, expected)
	require.NoError(t, err)
	// fmt.Print(key)
	// if err != nil {
	// 	fmt.Print("error: " + err.Error())
	// }

}

func TestFlyOverMac(t *testing.T) {
	ak := []byte{142, 19, 145, 119, 76, 2, 228, 18, 134, 111, 116, 45, 200, 172, 113, 219}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var baseTs uint32 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, 144)
	expected := []byte{254, 69, 18, 77, 4, 159, 168, 135, 97, 206, 53, 193, 28, 98, 23, 184}

	mac, err := hummingbird.FullMac(ak, dstIA, pktlen, baseTs, highResTs, buffer)

	require.Equal(t, mac, expected)
	require.NoError(t, err)
	//fmt.Print(mac)
}
