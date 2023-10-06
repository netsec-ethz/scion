// Copyright 2020 Anapaya Systems
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

package scion_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

var testInfoFields = []path.InfoField{
	{
		Peer:      false,
		ConsDir:   false,
		SegID:     0x111,
		Timestamp: 0x100,
	},
	{
		Peer:      false,
		ConsDir:   true,
		SegID:     0x222,
		Timestamp: 0x100,
	},
}

var testHopFields = []path.HopField{
	{
		ExpTime:     63,
		ConsIngress: 1,
		ConsEgress:  0,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 3,
		ConsEgress:  2,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 0,
		ConsEgress:  2,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 1,
		ConsEgress:  0,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
}

var testFlyoverFields = []path.HopField{
	{
		Flyover:      true,
		ExpTime:      63,
		ConsIngress:  1,
		ConsEgress:   0,
		Mac:          [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		ResID:        0,
		Bw:           4,
		ResStartTime: 2,
		Duration:     1,
	},
	{
		ExpTime:     63,
		ConsIngress: 3,
		ConsEgress:  2,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 0,
		ConsEgress:  2,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		Flyover:      true,
		ExpTime:      63,
		ConsIngress:  1,
		ConsEgress:   0,
		Mac:          [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		ResID:        0,
		Bw:           4,
		ResStartTime: 0,
		Duration:     1,
	},
}

var decodedTestPath = &scion.Decoded{
	Base: scion.Base{
		PathMeta: scion.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{2, 2, 0},
		},

		NumINF:  2,
		NumHops: 4,
	},
	InfoFields: testInfoFields,
	HopFields:  testHopFields,
}

var decodedHbirdTestPath = &scion.Decoded{
	Base: scion.Base{
		PathMeta: scion.MetaHdr{
			CurrINF:   0,
			CurrHF:    0,
			SegLen:    [3]uint8{8, 8, 0},
			BaseTS:    808,
			HighResTS: 1234,
		},
		NumINF:        2,
		NumHops:       16,
		IsHummingbird: true,
	},
	InfoFields: testInfoFields,
	HopFields:  testFlyoverFields,
}

var emptyDecodedTestPath = &scion.Decoded{
	Base:       scion.Base{},
	InfoFields: []path.InfoField{},
	HopFields:  []path.HopField{},
}

var rawPath = []byte("\x00\x00\x20\x80\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00" +
	"\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x03\x00\x02\x01\x02\x03" +
	"\x04\x05\x06\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x01\x00\x00\x01\x02" +
	"\x03\x04\x05\x06")

var rawHbirdPath = []byte("\x00\x02\x04\x00\x00\x00\x03\x28\x00\x00\x04\xd2" + //Pathmeta header
	"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" + //Infofields
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" + //flyoverfield 0
	"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" + //hopfield 1
	"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" + //hopfield 2
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x00\x00\x01") //flyoverfield 3

type pathCase struct {
	infos []bool
	hops  [][]uint16
}

type hbirdPathCase struct {
	infos []bool
	hops  [][][]uint16
}

var pathReverseCases = map[string]struct {
	input    pathCase
	want     pathCase
	inIdxs   [][2]int
	wantIdxs [][2]int
}{
	"1 segment, 2 hops": {
		input:    pathCase{[]bool{true}, [][]uint16{{11, 12}}},
		want:     pathCase{[]bool{false}, [][]uint16{{12, 11}}},
		inIdxs:   [][2]int{{0, 0}, {0, 1}},
		wantIdxs: [][2]int{{0, 1}, {0, 0}},
	},
	"1 segment, 5 hops": {
		input:    pathCase{[]bool{true}, [][]uint16{{11, 12, 13, 14, 15}}},
		want:     pathCase{[]bool{false}, [][]uint16{{15, 14, 13, 12, 11}}},
		inIdxs:   [][2]int{{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 4}},
		wantIdxs: [][2]int{{0, 4}, {0, 3}, {0, 2}, {0, 1}, {0, 0}},
	},
	"2 segments, 5 hops": {
		input:    pathCase{[]bool{true, false}, [][]uint16{{11, 12}, {13, 14, 15}}},
		want:     pathCase{[]bool{true, false}, [][]uint16{{15, 14, 13}, {12, 11}}},
		inIdxs:   [][2]int{{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}},
		wantIdxs: [][2]int{{1, 4}, {1, 3}, {0, 2}, {0, 1}, {0, 0}},
	},
	"3 segments, 9 hops": {
		input: pathCase{
			[]bool{true, false, false},
			[][]uint16{
				{11, 12},
				{13, 14, 15, 16},
				{17, 18, 19},
			},
		},
		want: pathCase{
			[]bool{true, true, false},
			[][]uint16{
				{19, 18, 17},
				{16, 15, 14, 13},
				{12, 11},
			},
		},
		inIdxs: [][2]int{
			{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}, {1, 5}, {2, 6}, {2, 7}, {2, 8},
		},
		wantIdxs: [][2]int{
			{2, 8}, {2, 7}, {1, 6}, {1, 5}, {1, 4}, {1, 3}, {0, 2}, {0, 1}, {0, 0},
		},
	},
}

var pathReverseCasesHbird = map[string]struct {
	input    hbirdPathCase
	want     hbirdPathCase
	inIdxs   [][2]int
	wantIdxs [][2]int
}{
	"1 segment, 2 hops": {
		input:    hbirdPathCase{[]bool{true}, [][][]uint16{{{11, 0}, {12, 1}}}},
		want:     hbirdPathCase{[]bool{false}, [][][]uint16{{{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}},
		wantIdxs: [][2]int{{0, 3}, {0, 0}},
	},
	"1 segment, 5 hops": {
		input:    hbirdPathCase{[]bool{true}, [][][]uint16{{{11, 1}, {12, 1}, {13, 0}, {14, 1}, {15, 0}}}},
		want:     hbirdPathCase{[]bool{false}, [][][]uint16{{{15, 0}, {14, 0}, {13, 0}, {12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 5}, {0, 10}, {0, 13}, {0, 18}},
		wantIdxs: [][2]int{{0, 12}, {0, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"2 segments, 5 hops": {
		input:    hbirdPathCase{[]bool{true, false}, [][][]uint16{{{11, 0}, {12, 0}}, {{13, 1}, {14, 1}, {15, 0}}}},
		want:     hbirdPathCase{[]bool{true, false}, [][][]uint16{{{15, 0}, {14, 0}, {13, 0}}, {{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}, {1, 6}, {1, 11}, {1, 16}},
		wantIdxs: [][2]int{{1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"3 segments, 9 hops": {
		input: hbirdPathCase{
			[]bool{true, false, false},
			[][][]uint16{
				{{11, 1}, {12, 0}},
				{{13, 0}, {14, 1}, {15, 1}, {16, 0}},
				{{17, 0}, {18, 1}, {19, 1}},
			},
		},
		want: hbirdPathCase{
			[]bool{true, true, false},
			[][][]uint16{
				{{19, 0}, {18, 0}, {17, 0}},
				{{16, 0}, {15, 0}, {14, 0}, {13, 0}},
				{{12, 0}, {11, 0}},
			},
		},
		inIdxs: [][2]int{
			{0, 0}, {0, 5}, {1, 8}, {1, 11}, {1, 16}, {1, 21}, {2, 24}, {2, 27}, {2, 32},
		},
		wantIdxs: [][2]int{
			{2, 24}, {2, 21}, {1, 18}, {1, 15}, {1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0},
		},
	},
}

func TestDecodedSerialize(t *testing.T) {
	b := make([]byte, decodedTestPath.Len())
	assert.NoError(t, decodedTestPath.SerializeTo(b))
	assert.Equal(t, rawPath, b)
}

func TestDecodedSerializeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	assert.Equal(t, rawHbirdPath, b)
}

func TestDecodedDecodeFromBytes(t *testing.T) {
	s := &scion.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(rawPath))
	assert.Equal(t, decodedTestPath, s)
}

func TestDecodedDecodeFromBytesHbird(t *testing.T) {
	s := &scion.Decoded{}
	s.Base.IsHummingbird = true
	assert.NoError(t, s.DecodeFromBytes(rawHbirdPath))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestDecodedSerializeDecode(t *testing.T) {
	b := make([]byte, decodedTestPath.Len())
	assert.NoError(t, decodedTestPath.SerializeTo(b))
	s := &scion.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, decodedTestPath, s)
}

func TestDecodedSerializeDecodeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	s := &scion.Decoded{}
	s.Base.IsHummingbird = true
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestDecodedReverse(t *testing.T) {
	for name, tc := range pathReverseCases {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				inputPath := mkDecodedPath(t, tc.input, uint8(tc.inIdxs[i][0]),
					uint8(tc.inIdxs[i][1]))
				wantPath := mkDecodedPath(t, tc.want, uint8(tc.wantIdxs[i][0]),
					uint8(tc.wantIdxs[i][1]))
				revPath, err := inputPath.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, wantPath, revPath)
			})
		}
	}
}

func TestDecodedReverseHbird(t *testing.T) {
	for name, tc := range pathReverseCasesHbird {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				inputPath := mkDecodedHbirdPath(t, tc.input, uint8(tc.inIdxs[i][0]),
					uint8(tc.inIdxs[i][1]))
				wantPath := mkDecodedHbirdPath(t, tc.want, uint8(tc.wantIdxs[i][0]),
					uint8(tc.wantIdxs[i][1]))
				revPath, err := inputPath.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, wantPath, revPath)
			})
		}
	}
}

func TestEmptyDecodedReverse(t *testing.T) {
	_, err := emptyDecodedTestPath.Reverse()
	assert.Error(t, err)
}

func TestDecodedToRaw(t *testing.T) {
	raw, err := decodedTestPath.ToRaw()
	assert.NoError(t, err)
	assert.Equal(t, rawTestPath, raw)
}

func TestDecodedToRawHbird(t *testing.T) {
	raw, err := decodedHbirdTestPath.ToRaw()
	assert.NoError(t, err)
	assert.Equal(t, rawHbirdTestPath, raw)
}

func mkDecodedPath(t *testing.T, pcase pathCase, infIdx, hopIdx uint8) *scion.Decoded {
	t.Helper()
	s := &scion.Decoded{}
	meta := scion.MetaHdr{
		CurrINF: infIdx,
		CurrHF:  hopIdx,
	}
	for i, dir := range pcase.infos {
		s.InfoFields = append(s.InfoFields, path.InfoField{ConsDir: dir})
		meta.SegLen[i] = uint8(len(pcase.hops[i]))
	}
	i := 0
	for _, hops := range pcase.hops {
		for _, hop := range hops {
			s.HopFields = append(s.HopFields, path.HopField{ConsIngress: hop, ConsEgress: hop})
			i++
		}
	}
	s.PathMeta = meta
	s.NumINF = len(pcase.infos)
	s.NumHops = i

	return s
}

func mkDecodedHbirdPath(t *testing.T, pcase hbirdPathCase, infIdx, hopIdx uint8) *scion.Decoded {
	t.Helper()
	s := &scion.Decoded{}
	s.Base.IsHummingbird = true
	meta := scion.MetaHdr{
		CurrINF:   infIdx,
		CurrHF:    hopIdx,
		BaseTS:    14,
		HighResTS: 15,
	}
	for _, dir := range pcase.infos {
		s.InfoFields = append(s.InfoFields, path.InfoField{ConsDir: dir})
	}
	i := 0
	for j, hops := range pcase.hops {
		for _, hop := range hops {
			f := hop[1] == 1
			s.HopFields = append(s.HopFields, path.HopField{Flyover: f, ConsIngress: hop[0], ConsEgress: hop[0], Mac: [6]byte{1, 2, 3, 4, 5, 6}, Duration: 2})
			if f {
				i += 5
				meta.SegLen[j] += 5
			} else {
				i += 3
				meta.SegLen[j] += 3
			}
		}
	}
	s.PathMeta = meta
	s.NumINF = len(pcase.infos)
	s.NumHops = i

	return s
}
