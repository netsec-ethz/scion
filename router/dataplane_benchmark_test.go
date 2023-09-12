// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
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

package router_test

import (
	"crypto/aes"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/mock_router"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

const (
	benchmarkPayloadLen = 10
)

// standard SCION benchmark for reference
func BenchmarkProcessScion(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Core,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 3, 0},
			},
			NumINF:  2,
			NumHops: 6,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 2},
			{ConsIngress: 7, ConsEgress: 31},
			{ConsIngress: 3, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 6},
			{ConsIngress: 8, ConsEgress: 9},
			{ConsIngress: 11, ConsEgress: 0},
		},
	}

	dpath.HopFields[1].Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[1])
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

func BenchmarkProcessScionXover(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 2,
				SegLen: [3]uint8{3, 3, 0},
			},
			NumINF:  2,
			NumHops: 6,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 2},
			{ConsIngress: 3, ConsEgress: 4},
			{ConsIngress: 7, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 31},
			{ConsIngress: 8, ConsEgress: 9},
			{ConsIngress: 11, ConsEgress: 0},
		},
	}

	dpath.HopFields[2].Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[2])
	dpath.HopFields[3].Mac = benchmarkScionMac(b, key, dpath.InfoFields[1], dpath.HopFields[3])
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// standard Hbird packet, no flyover
func BenchmarkProcessHbirdFlyoverless(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Core,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF: 3,
				SegLen: [3]uint8{9, 9, 0},
			},
			NumINF:   2,
			NumLines: 18,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 7, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 6}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[1].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[0],
		dpath.HopFields[1].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		//require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

func BenchmarkProcessHbirdFlyoverlessXover(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF: 6,
				SegLen: [3]uint8{9, 9, 0},
			},
			NumINF:   2,
			NumLines: 18,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 3, ConsEgress: 4}},
			{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[2].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[0],
		dpath.HopFields[2].HopField)
	dpath.HopFields[3].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[1],
		dpath.HopFields[3].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// To run any benchmark containing flyovers, temporarily modify
// dataplane_hbird.go:checkReservationBandwidth() such that it never fails,
// but still performs all operations
func BenchmarkProcessHbirdFlyover(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Core,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF:    3,
				SegLen:    [3]uint8{11, 9, 0},
				BaseTS:    util.TimeToSecs(now),
				HighResTS: 500 << 22,
			},
			NumINF:   2,
			NumLines: 20,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{Flyover: true, HopField: path.HopField{ConsIngress: 7, ConsEgress: 31},
				ResStartTime: 10, Duration: 180, Bw: 777},
			{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 6}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[1].HopField.Mac = benchmarkAggregateMac(b, key, sv, spkt.DstIA,
		benchmarkPayloadLen, 7, 31, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// To run any benchmark containing flyovers, temporarily modify
// dataplane_hbird.go:checkReservationBandwidth() such that it never fails,
// but still performs all operations
func BenchmarkProcessHbirdFlyoverXoverBrtransit(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF:    6,
				SegLen:    [3]uint8{11, 9, 0},
				BaseTS:    util.TimeToSecs(now),
				HighResTS: 500 << 22,
			},
			NumINF:   2,
			NumLines: 20,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 4, ConsEgress: 5}},
			{Flyover: true, HopField: path.HopField{ConsIngress: 7, ConsEgress: 0},
				ResID: 2345, ResStartTime: 10, Duration: 180, Bw: 777},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[2].HopField.Mac = benchmarkAggregateMac(b, key, sv, spkt.DstIA,
		benchmarkPayloadLen, 7, 31, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
	dpath.HopFields[3].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[1],
		dpath.HopFields[3].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

func BenchmarkProcessHbirdFlyoverXoverAstransit(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(7): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF:    6,
				SegLen:    [3]uint8{11, 9, 0},
				BaseTS:    util.TimeToSecs(now),
				HighResTS: 500 << 22,
			},
			NumINF:   2,
			NumLines: 20,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 4, ConsEgress: 5}},
			{Flyover: true, HopField: path.HopField{ConsIngress: 7, ConsEgress: 0},
				ResID: 2345, ResStartTime: 10, Duration: 180, Bw: 777},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[2].HopField.Mac = benchmarkAggregateMac(b, key, sv, spkt.DstIA,
		benchmarkPayloadLen, 7, 31, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
	dpath.HopFields[3].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[1],
		dpath.HopFields[3].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// Helper Functions for Benchmarking

func toBenchmarkMsg(b *testing.B, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
	b.Helper()
	ret := &ipv4.Message{}
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	spkt.PayloadLen = benchmarkPayloadLen
	payload := [benchmarkPayloadLen]byte{}
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload[:]))
	require.NoError(b, err)
	raw := buffer.Bytes()
	ret.Buffers = make([][]byte, 1)
	ret.Buffers[0] = make([]byte, 1500)
	copy(ret.Buffers[0], raw)
	ret.N = len(raw)
	ret.Buffers[0] = ret.Buffers[0][:ret.N]
	return ret
}

func benchmarkScionMac(b *testing.B, key []byte, info path.InfoField,
	hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(b, err)
	buffer := [path.MacLen]byte{}
	return path.MAC(mac, info, hf, buffer[:])
}

func benchmarkAggregateMac(b *testing.B, key, sv []byte, dst addr.IA, l, ingress, egress uint16,
	info path.InfoField, hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr) [path.MacLen]byte {

	scionMac := benchmarkScionMac(b, key, info, hf.HopField)
	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}
