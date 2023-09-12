package hummingbird_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
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

var testFlyoverFields = []hummingbird.FlyoverHopField{
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 2,
		Duration:     1,
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 3,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 0,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 0,
		Duration:     1,
	},
}

var otherTestFlyoverFields = []hummingbird.FlyoverHopField{
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 2,
		Duration:     1,
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 3,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 0,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
}

var decodedHbirdTestPath = &hummingbird.Decoded{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF:   0,
			CurrHF:    0,
			SegLen:    [3]uint8{8, 8, 0},
			BaseTS:    808,
			HighResTS: 1234,
		},
		NumINF:   2,
		NumLines: 16,
	},
	InfoFields:     testInfoFields,
	HopFields:      testFlyoverFields,
	FirstHopPerSeg: [2]uint8{2, 4},
}

var otherDecodedHbirdTestPath = &hummingbird.Decoded{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF:   0,
			CurrHF:    0,
			SegLen:    [3]uint8{8, 6, 0},
			BaseTS:    808,
			HighResTS: 1234,
		},
		NumINF:   2,
		NumLines: 14,
	},
	InfoFields:     testInfoFields,
	HopFields:      otherTestFlyoverFields,
	FirstHopPerSeg: [2]uint8{2, 4},
}

var emptyDecodedTestPath = &hummingbird.Decoded{
	Base:       hummingbird.Base{},
	InfoFields: []path.InfoField{},
	HopFields:  []hummingbird.FlyoverHopField{},
}

var rawHbirdPath = []byte("\x00\x02\x04\x00\x00\x00\x03\x28\x00\x00\x04\xd2" +
	"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" +
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" +
	"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" +
	"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" +
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x00\x00\x01")

var otherRawHbirdPath = []byte("\x00\x02\x03\x00\x00\x00\x03\x28\x00\x00\x04\xd2" +
	"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" +
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" +
	"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" +
	"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" +
	"\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06")

type hbirdPathCase struct {
	infos []bool
	hops  [][][]uint16
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
		input: hbirdPathCase{[]bool{true},
			[][][]uint16{{{11, 1}, {12, 1}, {13, 0}, {14, 1}, {15, 0}}}},
		want: hbirdPathCase{[]bool{false},
			[][][]uint16{{{15, 0}, {14, 0}, {13, 0}, {12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 5}, {0, 10}, {0, 13}, {0, 18}},
		wantIdxs: [][2]int{{0, 12}, {0, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"2 segments, 5 hops": {
		input: hbirdPathCase{[]bool{true, false},
			[][][]uint16{{{11, 0}, {12, 0}}, {{13, 1}, {14, 1}, {15, 0}}}},
		want: hbirdPathCase{[]bool{true, false},
			[][][]uint16{{{15, 0}, {14, 0}, {13, 0}}, {{12, 0}, {11, 0}}}},
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

func TestDecodedSerializeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	assert.Equal(t, rawHbirdPath, b)
}

func TestDecodedDecodeFromBytesHbird(t *testing.T) {
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(rawHbirdPath))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestDecodedDecodeFromBytesNoFlyovers(t *testing.T) {
	// p is the scion decoded path we would observe using the Tiny topology of the
	// topology generator, when going from 111 to 112. This is one up segment with 2 hops, followed
	// by a down segment with two hops as well. There is a cross over at core 110 gluing both.
	p := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			{}, // up
			{}, // down
		},
		HopFields: []path.HopField{
			{}, // 111: 0->41 up
			{}, // 110: 1->0  up
			{}, // 110: 0->2  down
			{}, // 112: 1->0  down
		},
	}

	// Create a hummingbird path from the scion one.
	hbird := &hummingbird.Decoded{}
	hbird.ConvertFromScionDecoded(*p) // SegLen will be [6,6,0] after this

	// Check the hummingbird path is correct by serializing and deserializing it.
	buf := make([]byte, hbird.Len())
	err := hbird.SerializeTo(buf)
	assert.NoError(t, err)
	// Deserialize.
	hbird = &hummingbird.Decoded{}
	err = hbird.DecodeFromBytes(buf)
	assert.NoError(t, err)
}

func TestDecodedSerializeDecodeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestOtherDecodedSerializeHbird(t *testing.T) {
	b := make([]byte, otherDecodedHbirdTestPath.Len())
	assert.NoError(t, otherDecodedHbirdTestPath.SerializeTo(b))
	assert.Equal(t, otherRawHbirdPath, b)
}

func TestOtherDecodedDecodeFromBytesHbird(t *testing.T) {
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(otherRawHbirdPath))
	assert.Equal(t, otherDecodedHbirdTestPath, s)
}

func TestOtherDecodedSerializeDecodeHbird(t *testing.T) {
	b := make([]byte, otherDecodedHbirdTestPath.Len())
	assert.NoError(t, otherDecodedHbirdTestPath.SerializeTo(b))
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, otherDecodedHbirdTestPath, s)
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

func TestDecodedToRawHbird(t *testing.T) {
	raw, err := decodedHbirdTestPath.ToRaw()
	assert.NoError(t, err)
	assert.Equal(t, rawHbirdTestPath, raw)
}

func TestInfIndexForHFIndex(t *testing.T) {
	cases := map[string]struct {
		path     hummingbird.Decoded
		expected []uint8 // the INF indices of each hop field in the test case
	}{
		"empty": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{0, 0, 0},
					},
				},
			},
		},
		"one_segment_o": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{3, 0, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
				},
			},
			expected: []uint8{0},
		},
		// one_segment_oxx means there is one segment with three hops, first is not flyover,
		// second and third are.
		"one_segment_oxx": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{13, 0, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
					{Flyover: true},
					{Flyover: true},
				},
			},
			expected: []uint8{0, 0, 0},
		},
		"two_segments_o_oxx": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{3, 13, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
					{Flyover: false},
					{Flyover: true},
					{Flyover: true},
				},
			},
			expected: []uint8{0, 1, 1, 1},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			for i := range tc.path.HopFields {
				got := tc.path.InfIndexForHFIndex(uint8(i))
				assert.Equal(t, tc.expected[i], got)
			}
			assert.Panics(t, func() {
				tc.path.InfIndexForHFIndex(uint8(len(tc.path.HopFields)) + 1)
			})
		})
	}
}

func mkDecodedHbirdPath(t *testing.T, pcase hbirdPathCase,
	infIdx, hopIdx uint8) *hummingbird.Decoded {
	t.Helper()
	s := &hummingbird.Decoded{}
	meta := hummingbird.MetaHdr{
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
			s.HopFields = append(s.HopFields, hummingbird.FlyoverHopField{
				HopField: path.HopField{ConsIngress: hop[0], ConsEgress: hop[0],
					Mac: [6]byte{1, 2, 3, 4, 5, 6}},
				Flyover:  f,
				Duration: 2})
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
	s.NumLines = i

	return s
}
