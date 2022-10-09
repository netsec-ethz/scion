// Copyright 2019 ETH Zurich, Anapaya Systems
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

package reservation

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSegmentIDFromRaw(t *testing.T) {
	id, err := IDFromRaw(xtest.MustParseHexString("ffaa00001101facecafe"))
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseAS("ffaa:0:1101"), id.ASID)
	require.Equal(t, xtest.MustParseHexString("facecafe"), id.Suffix)
	require.True(t, id.IsSegmentID())
}

func TestIDRead(t *testing.T) {
	reference := ID{
		ASID: xtest.MustParseAS("ffaa:0:1101"),
	}
	reference.Suffix = xtest.MustParseHexString("facecafe")
	raw := make([]byte, IDSegLen)
	n, err := reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, IDSegLen, n)
	require.Equal(t, xtest.MustParseHexString("ffaa00001101facecafe"), raw)
	require.True(t, reference.IsSegmentID())
	require.Equal(t, n, reference.Len())

	// E2E
	reference.Suffix = xtest.MustParseHexString("facecafedeadbeeff00dcafe")
	raw = make([]byte, IDE2ELen)
	n, err = reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, IDE2ELen, n)
	require.Equal(t, xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00dcafe"), raw)
	require.True(t, reference.IsE2EID())
	require.Equal(t, n, reference.Len())
}

func TestIDString(t *testing.T) {
	cases := []struct {
		ID  ID
		Str string
	}{
		{ID: mustParseID("ff0000001101facecafe"), Str: "ff00:0:1101-facecafe"},
		{ID: mustParseID("ff000000110100000000"), Str: "ff00:0:1101-00000000"},
	}
	for i, c := range cases {
		name := fmt.Sprintf("case %d", i)
		t.Run(name, func(t *testing.T) {
			c := c
			t.Parallel()
			require.Equal(t, c.Str, c.ID.String())
		})
	}
}

func TestE2EIDFromRaw(t *testing.T) {
	raw := xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00dcafe")
	id, err := IDFromRaw(raw)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseAS("ffaa:0:1101"), id.ASID)
	require.Equal(t, xtest.MustParseHexString("facecafedeadbeeff00dcafe"), id.Suffix)
	require.True(t, id.IsE2EID())
}

func TestIDCopy(t *testing.T) {
	id1 := ID{
		ASID:   xtest.MustParseAS("ff00:0:111"),
		Suffix: make([]byte, IDSuffixE2ELen),
	}
	id1.Suffix[1] = 1
	id2 := id1.Copy()
	id2.Suffix[1] = 2
	require.Equal(t, uint8(1), id1.Suffix[1])
	require.Equal(t, uint8(2), id2.Suffix[1])
}

func TestTickFromTime(t *testing.T) {
	require.Equal(t, Tick(0), TickFromTime(time.Unix(0, 0)))
	require.Equal(t, Tick(0), TickFromTime(time.Unix(3, 999999)))
	require.Equal(t, Tick(1), TickFromTime(time.Unix(4, 0)))
}

func TestTickToTime(t *testing.T) {
	require.Equal(t, time.Unix(0, 0), Tick(0).ToTime())
	require.Equal(t, time.Unix(4, 0), Tick(1).ToTime())
	require.Equal(t, time.Unix(0, 0), TickFromTime(time.Unix(0, 0)).ToTime())
	require.Equal(t, time.Unix(0, 0), TickFromTime(time.Unix(3, 999999)).ToTime())
	require.Equal(t, time.Unix(4, 0), TickFromTime(time.Unix(4, 0)).ToTime())
}

func TestTickFromDuration(t *testing.T) {
	cases := map[time.Duration]Tick{
		0:                                       0,
		1:                                       1,
		time.Duration(3300 * time.Millisecond):  1,
		time.Duration(4 * time.Second):          1,
		time.Duration(4*time.Second + 1):        2,
		time.Duration(8001 * time.Millisecond):  3,
		time.Duration(11999 * time.Millisecond): 3,
	}
	for dur, tick := range cases {
		t.Run(dur.String(), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tick, TicksFromDuration(dur))
		})
	}
}

func TestTickToDuration(t *testing.T) {
	cases := map[Tick]time.Duration{
		0: 0,
		1: time.Duration(4 * time.Second),
	}
	for tick, dur := range cases {
		name := fmt.Sprintf("%d", tick)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, dur, tick.ToDuration())
		})
	}
}

func TestValidateBWCls(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := BWCls(i)
		err := c.Validate()
		require.NoError(t, err)
	}
	c := BWCls(64)
	err := c.Validate()
	require.Error(t, err)
}

func TestBWClsToKbps(t *testing.T) {
	cases := map[BWCls]uint64{
		0:  0,
		1:  16,
		2:  22,
		3:  32,
		5:  64,
		7:  128,
		13: 1024,
		63: 32 * 1024 * 1024 * 1024, // 32 TBps
	}
	for cls, bw := range cases {
		name := fmt.Sprintf("case for %d", cls)
		t.Run(name, func(t *testing.T) {
			cls := cls
			bw := bw
			t.Parallel()
			require.Equal(t, bw, cls.ToKbps())
		})
	}
}

func TestBWClsFromBW(t *testing.T) {
	cases := map[uint64]BWCls{
		0:                       0,
		1:                       0, // class 0 because when granted it won't exceed 1 Kbps
		16:                      1,
		22:                      1,
		23:                      2,
		32:                      3,
		64:                      5,
		1024:                    13,
		4096:                    17,
		4000:                    16,
		4097:                    17,
		32 * 1024 * 1024 * 1024: 63,
	}
	for bw, cls := range cases {
		bw, cls := bw, cls
		name := fmt.Sprintf("case for %d", bw)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, cls, BWClsFromBW(bw), "BW fails at %d: expected %d got %d",
				int(bw), cls, BWClsFromBW(bw))
		})
	}
}

func TestMaxBWCls(t *testing.T) {
	cases := []struct{ a, b, max BWCls }{
		{a: 1, b: 1, max: 1},
		{a: 0, b: 1, max: 1},
		{a: 255, b: 1, max: 255},
	}
	for i, c := range cases {
		name := fmt.Sprintf("case %d", i)
		t.Run(name, func(t *testing.T) {
			c := c
			t.Parallel()
			require.Equal(t, c.max, MaxBWCls(c.a, c.b))
		})
	}
}

func TestMinBWCls(t *testing.T) {
	cases := []struct{ a, b, min BWCls }{
		{a: 1, b: 1, min: 1},
		{a: 0, b: 1, min: 0},
		{a: 255, b: 0, min: 0},
	}
	for i, c := range cases {
		name := fmt.Sprintf("case %d", i)
		t.Run(name, func(t *testing.T) {
			c := c
			t.Parallel()
			require.Equal(t, c.min, MinBWCls(c.a, c.b))
		})
	}
}

func TestSplitForData(t *testing.T) {
	cases := map[SplitCls]float64{
		2:  0.5,
		4:  0.75,
		6:  0.875,
		7:  0.91161,
		8:  0.9375,
		10: 0.96875,
		12: 0.984375,
		16: 0.99609375,
	}
	for cls, split := range cases {
		cls, split := cls, split
		name := fmt.Sprintf("case for %d", cls)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.InDelta(t, split, cls.SplitForData(), 0.00001)
		})
	}
}

func TestValidateRLC(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := RLC(i)
		err := c.Validate()
		require.NoError(t, err)
	}
	c := RLC(64)
	err := c.Validate()
	require.Error(t, err)
}

func TestValidateIndexNumber(t *testing.T) {
	for i := 0; i < 16; i++ {
		idx := IndexNumber(i)
		err := idx.Validate()
		require.NoError(t, err)
	}
	idx := IndexNumber(16)
	err := idx.Validate()
	require.Error(t, err)
}

func TestIndexNumberArithmetic(t *testing.T) {
	var idx IndexNumber = 1
	x := idx.Add(IndexNumber(15))
	require.Equal(t, IndexNumber(0), x)
	x = idx.Sub(IndexNumber(2))
	require.Equal(t, IndexNumber(15), x)
	// distance from 2 to 0 = 0 - 2 = 14 mod 16
	x = IndexNumber(2)
	distance := IndexNumber(0).Sub(x)
	require.Equal(t, IndexNumber(14), distance)
	// distance from 2 to 4
	distance = IndexNumber(4).Sub(x)
	require.Equal(t, IndexNumber(2), distance)
}

func TestValidatePathType(t *testing.T) {
	validTypes := []PathType{
		CorePath,
		DownPath,
		UpPath,
		PeeringDownPath,
		PeeringUpPath,
		E2EPath,
	}
	for _, vt := range validTypes {
		err := vt.Validate()
		require.NoError(t, err)
	}
	err := UnknownPath.Validate()
	require.Error(t, err)
	err = _lastvaluePath.Validate()
	require.Error(t, err)
}

func TestValidateInfoField(t *testing.T) {
	infoField := InfoField{
		ExpirationTick: 0,
		BWCls:          0,
		RLC:            0,
		Idx:            0,
		PathType:       CorePath,
	}
	err := infoField.Validate()
	require.NoError(t, err)

	otherIF := infoField
	otherIF.BWCls = 64
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.RLC = 64
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.Idx = 16
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.PathType = _lastvaluePath
	err = otherIF.Validate()
	require.Error(t, err)
}

func TestInfoFieldFromRaw(t *testing.T) {
	reference := newInfoField()
	rawReference := newInfoFieldRaw()
	info, err := InfoFieldFromRaw(rawReference)
	require.NoError(t, err)
	require.Equal(t, reference, *info)
}

func TestInfoFieldRead(t *testing.T) {
	reference := newInfoField()
	rawReference := newInfoFieldRaw()
	raw := make([]byte, InfoFieldLen)
	// pollute the buffer with garbage
	for i := 0; i < InfoFieldLen; i++ {
		raw[i] = byte(i % 256)
	}
	n, err := reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, InfoFieldLen, n)
	require.Equal(t, rawReference, raw)
}

func TestInfoFieldToRaw(t *testing.T) {
	val := newInfoField()
	reference := &val
	rawReference := newInfoFieldRaw()
	require.Equal(t, rawReference, reference.ToRaw())
	reference = nil
	require.Equal(t, ([]byte)(nil), reference.ToRaw())
}

func TestValidatePathEndProperties(t *testing.T) {
	for i := 0; i < 4; i++ {
		pep := PathEndProps(i)
		err := pep.Validate()
		require.NoError(t, err)
	}
	pep := PathEndProps(4)
	err := pep.Validate()
	require.Error(t, err)

	for i := 0; i < 4; i++ {
		pep := PathEndProps(i << 4)
		err := pep.Validate()
		require.NoError(t, err)
	}
	pep = PathEndProps(4 << 4)
	err = pep.Validate()
	require.Error(t, err)

	pep = PathEndProps(0x10 | 0x04)
	err = pep.Validate()
	require.Error(t, err)
}

func TestValidatePathEndPropsWithPathType(t *testing.T) {
	cases := []struct {
		PT    PathType
		EP    PathEndProps
		Valid bool
	}{
		// core paths
		{CorePath, StartLocal | EndLocal, true},
		{CorePath, StartLocal | EndLocal | EndTransfer, true},
		{CorePath, StartTransfer | EndTransfer, true},
		{CorePath, StartLocal, true},
		{CorePath, StartTransfer, true},
		{CorePath, EndLocal, false},
		{CorePath, 0, false},
		// up paths
		{UpPath, StartLocal, true},
		{UpPath, StartLocal | EndLocal | EndTransfer, true},
		{UpPath, 0, false},
		{UpPath, StartTransfer, false},
		{UpPath, StartTransfer | StartLocal, false},
		// down paths
		{DownPath, EndLocal, true},
		{DownPath, EndLocal | StartLocal | StartTransfer, true},
		{DownPath, 0, false},
		{DownPath, EndTransfer, false},
		{DownPath, EndTransfer | EndLocal, false},
		// peering up paths
		{PeeringUpPath, StartLocal | EndLocal, true},
		{PeeringUpPath, StartLocal | EndLocal | EndTransfer, true},
		{PeeringUpPath, 0, false},
		{PeeringUpPath, StartLocal, false},
		{PeeringUpPath, StartLocal | StartTransfer | EndLocal, false},
		{PeeringUpPath, StartTransfer | EndLocal, false},
		{PeeringUpPath, EndLocal, false},
		// peering down paths
		{PeeringDownPath, EndLocal | StartLocal, true},
		{PeeringDownPath, EndLocal | StartLocal | StartTransfer, true},
		{PeeringDownPath, 0, false},
		{PeeringDownPath, EndLocal, false},
		{PeeringDownPath, EndLocal | EndTransfer | StartLocal, false},
		{PeeringDownPath, EndTransfer | StartLocal, false},
		{PeeringDownPath, StartLocal, false},
	}
	for i, c := range cases {
		name := fmt.Sprintf("iteration %d", i)
		t.Run(name, func(t *testing.T) {
			c := c
			t.Parallel()
			err := c.EP.ValidateWithPathType(c.PT)
			if c.Valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAllocationBeadsMinMax(t *testing.T) {
	cases := []struct {
		Trail AllocationBeads
		Min   BWCls
	}{
		{newAllocationBeads(), 0},
		{newAllocationBeads(0, 1), 1},
		{newAllocationBeads(0, 3, 0, 1), 1},
		{newAllocationBeads(0, 3, 0, 255), 3},
	}
	for i, c := range cases {
		name := fmt.Sprintf("iteration %d", i)
		t.Run(name, func(t *testing.T) {
			c := c
			t.Parallel()
			require.Equal(t, c.Min, c.Trail.MinMax())
		})
	}
}

func TestValidateToken(t *testing.T) {
	tok := newToken(t)
	err := tok.Validate()
	require.NoError(t, err)
	tok.HopFields = []HopField{}
	err = tok.Validate()
	require.Error(t, err)
}

func TestTokenLen(t *testing.T) {
	tok := newToken(t)
	require.Equal(t, len(newTokenRaw()), tok.Len())
}

func TestTokenFromRaw(t *testing.T) {
	referenceRaw := newTokenRaw()
	reference := newToken(t)
	tok, err := TokenFromRaw(referenceRaw)
	require.NoError(t, err)
	require.Equal(t, reference, *tok)

	// buffer too small
	_, err = TokenFromRaw(referenceRaw[:3])
	require.Error(t, err)

	// one hop field less
	tok, err = TokenFromRaw(referenceRaw[:len(referenceRaw)-HopFieldLen])
	require.NoError(t, err)
	require.Len(t, tok.HopFields, len(reference.HopFields)-1)
}
func TestTokenRead(t *testing.T) {
	tok := newToken(t)
	rawReference := newTokenRaw()
	buf := make([]byte, len(rawReference))
	c, err := tok.Read(buf)
	require.NoError(t, err)
	require.Equal(t, len(buf), c)
	require.Equal(t, rawReference, buf)

	// buffer too small
	_, err = tok.Read(buf[:len(rawReference)-1])
	require.Error(t, err)
}

func TestTokenToRaw(t *testing.T) {
	tok := newToken(t)
	raw := newTokenRaw()
	require.Equal(t, raw, tok.ToRaw())
}

func TestTokenGetFirstNHopFields(t *testing.T) {
	cases := map[string]struct {
		token    Token
		n        int
		expected []HopField
	}{
		"empty": {
			token: Token{
				InfoField: InfoField{PathType: CorePath},
				HopFields: []HopField{*newHopField(t, 1, 11, xtest.MustParseHexString("01234567"))},
			},
			n:        0,
			expected: nil,
		},
		"last": {
			token: Token{
				InfoField: InfoField{PathType: CorePath},
				HopFields: []HopField{
					*newHopField(t, 1, 11, xtest.MustParseHexString("01234567")),
					*newHopField(t, 2, 11, xtest.MustParseHexString("11234567")),
				},
			},
			n:        1,
			expected: []HopField{*newHopField(t, 2, 11, xtest.MustParseHexString("11234567"))},
		},
		"all": {
			token: Token{
				InfoField: InfoField{PathType: CorePath},
				HopFields: []HopField{
					*newHopField(t, 1, 11, xtest.MustParseHexString("01234567")),
					*newHopField(t, 2, 11, xtest.MustParseHexString("11234567")),
				},
			},
			n: 2,
			expected: []HopField{
				*newHopField(t, 1, 11, xtest.MustParseHexString("01234567")),
				*newHopField(t, 2, 11, xtest.MustParseHexString("11234567")),
			},
		},
		"last_downpath": {
			token: Token{
				InfoField: InfoField{PathType: DownPath},
				HopFields: []HopField{
					*newHopField(t, 1, 11, xtest.MustParseHexString("01234567")),
					*newHopField(t, 2, 11, xtest.MustParseHexString("11234567")),
				},
			},
			n:        1,
			expected: []HopField{*newHopField(t, 1, 11, xtest.MustParseHexString("01234567"))},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.token.GetFirstNHopFields(tc.n)
			require.Equal(t, tc.expected, got)
		})
	}
}

func newInfoField() InfoField {
	return InfoField{
		ExpirationTick: 384555855,
		BWCls:          13,
		RLC:            4,
		Idx:            2,
		PathType:       E2EPath,
	}
}

func newInfoFieldRaw() []byte {
	return xtest.MustParseHexString("16ebdb4f0d042600")
}

func newHopField(t *testing.T, ingress, egress uint16, mac []byte) *HopField {
	hf := HopField{
		Ingress: ingress,
		Egress:  egress,
	}
	if len(mac) < len(hf.Mac) {
		require.FailNow(t, "mac is too short: %d", "len:%d", len(mac))
	}
	copy(hf.Mac[:], mac)
	return &hf
}

func newToken(t *testing.T) Token {
	return Token{
		InfoField: newInfoField(),
		HopFields: []HopField{
			*newHopField(t, 1, 2, xtest.MustParseHexString("badcffee")),
			*newHopField(t, 1, 2, xtest.MustParseHexString("baadf00d")),
		},
	}
}
func newTokenRaw() []byte {
	return xtest.MustParseHexString("16ebdb4f0d04260000010002badcffee00010002baadf00d")
}

func mustParseID(s string) ID {
	id, err := IDFromRaw(xtest.MustParseHexString(s))
	if err != nil {
		panic(err)
	}
	return *id
}

// newAllocationBeads (1,2,3,4) returns two beads {alloc: 1, max: 2}, {alloc:3, max:4}
func newAllocationBeads(beads ...BWCls) AllocationBeads {
	if len(beads)%2 != 0 {
		panic("must have an even number of parameters")
	}
	ret := make(AllocationBeads, len(beads)/2)
	for i := 0; i < len(beads); i += 2 {
		ret[i/2] = AllocationBead{AllocBW: beads[i], MaxBW: beads[i+1]}
	}
	return ret
}
