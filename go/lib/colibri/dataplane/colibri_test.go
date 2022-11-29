// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package colibri_test

import (
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	sheader "github.com/scionproto/scion/go/lib/slayers/scion"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestMACInput(t *testing.T) {
	want := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0x0, 0x0, 0x12,
		0x34, 0x12, 0x34, 0x0, 0x60, 0x0, 0x1, 0x0, 0x2, 0xff, 0x0, 0x0, 0x0, 0x2, 0x22, 0x0, 0x0}

	s := createScionCmnAddrHdr()
	c := createColibriPath()
	c.InfoField.ResIdSuffix = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b}
	c.InfoField.ExpTick = 0x1234
	c.InfoField.BwCls = 0x12
	c.InfoField.Rlc = 0x34
	c.InfoField.Ver = 0x6

	buffer := make([]byte, libcolibri.LengthInputDataRound16)
	libcolibri.MACInputStatic(buffer, c.InfoField.ResIdSuffix, c.InfoField.ExpTick,
		reservation.BWCls(c.InfoField.BwCls), reservation.RLC(c.InfoField.Rlc),
		c.InfoField.C, c.InfoField.R, reservation.IndexNumber(c.InfoField.Ver),
		s.SrcIA.AS(), s.DstIA.AS(), c.HopFields[0].IngressId, c.HopFields[0].EgressId)
	assert.Equal(t, want, buffer)
}

func TestMACInputSigma(t *testing.T) {
	want := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0x12, 0x34, 0x56,
		0x78, 0x12, 0x34, 0x0, 0x60, 0x0, 0x1, 0x0, 0x2, 0xff, 0x0, 0x0, 0x0, 0x2, 0x22, 0x44, 0xa,
		0x0, 0x0, 0x64, 0x1, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	s := createScionCmnAddrHdr()
	c := createColibriPath()
	c.InfoField.ResIdSuffix = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b}
	c.InfoField.ExpTick = 0x12345678
	c.InfoField.BwCls = 0x12
	c.InfoField.Rlc = 0x34
	c.InfoField.Ver = 0x6

	var buffer [64]byte
	inLen, err := libcolibri.MACInputSigma(buffer[:], s, c.InfoField, c.HopFields[0])
	assert.NoError(t, err)
	assert.Equal(t, want, buffer[:inLen])
}

func TestMACInputE2E(t *testing.T) {
	want := []byte{0x12, 0x34, 0x56, 0x78, 0x7, 0x0, 0x4, 0x1, 0x01,
		0x0c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	// Total size of packet (cmn/addr/colibri/payload) = 268 = 0x10c

	s := createScionCmnAddrHdr()
	c := createColibriPath()
	c.InfoField.OrigPayLen = 120
	var tsRel uint32 = 0x12345678
	packetTimestamp := libcolibri.CreateColibriTimestamp(tsRel, 7, 1025)

	var input [16]byte
	err := libcolibri.MACInputE2E(input[:], packetTimestamp, c.InfoField, s)
	assert.NoError(t, err)
	assert.Equal(t, want, input[:])
}

func TestCreateColibriTimeStamp(t *testing.T) {
	want := []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03}
	ts := libcolibri.CreateColibriTimestamp(1, 2, 3)
	assert.Equal(t, want, ts[:])

}

func TestTimestamp(t *testing.T) {
	testCases := []colibri.Timestamp{
		timestampFromNumber(0),
		timestampFromNumber(1),
		timestampFromNumber(4041796896134235295),
		timestampFromNumber(12590502804441994123),
		timestampFromNumber(2265056923175922768),
		timestampFromNumber(9648491470230957773),
		timestampFromNumber(math.MaxInt32),
		timestampFromNumber(0xbbbbbbbbff123456),
	}

	for _, want := range testCases {
		tsRel, coreID, coreCounter := libcolibri.ParseColibriTimestamp(want)
		t.Logf("tsRel: %x coreID: %x coreCounter: %x", tsRel, coreID, coreCounter)
		got := libcolibri.CreateColibriTimestamp(tsRel, coreID, coreCounter)
		assert.Equal(t, want, got)
	}
}

func TestCreateTsRel(t *testing.T) {
	// expTick encodes the current time plus something between 4 and 8 seconds.
	expTick := uint32(time.Now().Unix()/4) + 2

	// Incrementing/decrementing tsRel by one corresponds to adding/subtracting 4 seconds
	testCases := map[uint32]bool{
		0:           false,
		expTick - 2: false,
		expTick - 1: true,
		expTick:     true,
		expTick + 1: true,
		expTick + 2: true,
		expTick + 3: false,
	}
	for expTick, want := range testCases {
		_, err := libcolibri.CreateTsRel(expTick, time.Now())
		if want == true {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestTimestampVerification(t *testing.T) {
	// expTick encodes the current time plus something between 8 and 12 seconds.
	expTick := uint32(time.Now().Unix()/4) + 3

	tsRel, err := libcolibri.CreateTsRel(expTick, time.Now())
	assert.NoError(t, err)
	var stepsPerSecond uint32 = 250000000 // 1 step corresponds to 4ns

	testCases := map[uint32]bool{
		tsRel + (stepsPerSecond * 3 / 2): false,
		tsRel + (stepsPerSecond / 2):     true,
		tsRel:                            true,
		tsRel - (stepsPerSecond / 2):     true,
		tsRel - (stepsPerSecond * 3 / 2): true,
		tsRel - (stepsPerSecond * 5 / 2): true,
		tsRel - (stepsPerSecond * 7 / 2): false,
	}

	for tsRel, want := range testCases {
		packetTimestamp := libcolibri.CreateColibriTimestamp(tsRel, 0, 0)
		assert.Equal(t, want, libcolibri.VerifyTimestamp(expTick, packetTimestamp, time.Now()))
	}
}

func TestStaticHVFVerification(t *testing.T) {
	s := createScionCmnAddrHdr()
	c := createColibriPath()

	c.InfoField.C = true
	// Generate MAC
	privateKey, err := libcolibri.InitColibriKey([]byte("a_random_key_123"))
	require.NoError(t, err)
	var mac [4]byte
	err = libcolibri.MACStatic(mac[:], privateKey, c.InfoField,
		c.HopFields[c.InfoField.CurrHF], s.SrcIA.AS(), s.DstIA.AS())
	assert.NoError(t, err)
	c.HopFields[c.InfoField.CurrHF].Mac = mac[:]

	// Verify MAC correctly
	err = libcolibri.VerifyMAC(privateKey, c.PacketTimestamp, c.InfoField,
		c.HopFields[c.InfoField.CurrHF], s)
	assert.NoError(t, err)

	// Verify MAC with wrong key
	privateKey, err = libcolibri.InitColibriKey([]byte("a_random_key_456"))
	require.NoError(t, err)
	err = libcolibri.VerifyMAC(privateKey, c.PacketTimestamp, c.InfoField,
		c.HopFields[c.InfoField.CurrHF], s)
	assert.Error(t, err)

	// Verify MAC with a reversed path
	privateKey, err = libcolibri.InitColibriKey([]byte("a_random_key_123"))
	require.NoError(t, err)
	_, err = c.Reverse()
	assert.NoError(t, err)
	s.SrcIA, s.DstIA = s.DstIA, s.SrcIA
	err = libcolibri.VerifyMAC(privateKey, c.PacketTimestamp, c.InfoField,
		c.HopFields[c.InfoField.CurrHF], s)
	assert.NoError(t, err)
}

func TestPacketHVFVerification(t *testing.T) {
	s := createScionCmnAddrHdr()
	c := createColibriPath()

	c.InfoField.C = false
	// Generate MAC
	privateKey, err := libcolibri.InitColibriKey([]byte("a_random_key_123"))
	require.NoError(t, err)
	var mac [4]byte
	err = libcolibri.MACE2E(mac[:], privateKey, c.InfoField, c.PacketTimestamp,
		c.HopFields[c.InfoField.CurrHF], s)
	assert.NoError(t, err)
	c.HopFields[c.InfoField.CurrHF].Mac = mac[:]

	// TODO(juagargi) uncomment after fixing the way we compute the E2E MAC
	// // Verify MAC correctly
	// err = libcolibri.VerifyMAC(privateKey, c.PacketTimestamp, c.InfoField,
	// 	c.HopFields[c.InfoField.CurrHF], s)
	// assert.NoError(t, err)

	// Verify MAC with wrong key
	privateKey, err = libcolibri.InitColibriKey([]byte("a_random_key_456"))
	require.NoError(t, err)
	err = libcolibri.VerifyMAC(privateKey, c.PacketTimestamp, c.InfoField,
		c.HopFields[c.InfoField.CurrHF], s)
	assert.Error(t, err)

}

func createScionCmnAddrHdr() *slayers.SCION {
	spkt := &slayers.SCION{
		SCION: sheader.SCION{
			SrcIA:      xtest.MustParseIA("2-ff00:0:222"),
			PayloadLen: 120,
		},
	}
	ip4AddrSrc := &net.IPAddr{IP: net.ParseIP("10.0.0.100")}
	ip4AddrDst := &net.IPAddr{IP: net.ParseIP("1.2.3.4")}
	spkt.SetSrcAddr(ip4AddrSrc)
	spkt.SetDstAddr(ip4AddrDst)

	spkt.DstAddrType = sheader.T4Svc
	spkt.DstAddrLen = sheader.AddrLen4
	spkt.SrcAddrType = sheader.T4Svc
	spkt.SrcAddrLen = sheader.AddrLen4
	return spkt
}

func createColibriPath() *colibri.ColibriPath {
	ts := libcolibri.CreateColibriTimestamp(1, 2, 3)
	colibripath := &colibri.ColibriPath{
		PacketTimestamp: ts,
		InfoField: &colibri.InfoField{
			CurrHF:      0,
			HFCount:     10,
			ResIdSuffix: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			ExpTick:     uint32(time.Now().Unix() / 4),
			BwCls:       1,
			Rlc:         2,
			Ver:         3,
		},
	}
	hopfields := make([]*colibri.HopField, 10)
	for i := range hopfields {
		hf := &colibri.HopField{
			IngressId: 1,
			EgressId:  2,
			Mac:       []byte{1, 2, 3, 4},
		}
		hopfields[i] = hf
	}
	colibripath.HopFields = hopfields
	return colibripath
}

func timestampFromNumber(n uint64) colibri.Timestamp {
	ts := colibri.Timestamp{}
	binary.BigEndian.PutUint64(ts[:], n)
	return ts
}
