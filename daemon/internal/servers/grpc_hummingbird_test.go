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

package servers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	pathlayers "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/hummingbirddb"
	"github.com/stretchr/testify/require"
)

const currUnixTimestamp = 100

// TestGetReservation checks that given a set of SCION paths, the functions getting the
// reservation correctly finds the appropriate flyovers and uses them.
func TestGetReservation(t *testing.T) {
	cases := map[string]struct {
		// paths' hops, like { {0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0} , ... }
		scionPaths [][]any
		expected   [][]any // this is a slice of flyovers allowing nils in it
		flyoverDB  [][]any
	}{
		"onepath_oneflyover": {
			scionPaths: [][]any{
				{
					0, "1-ff00:0:1", 1,
					2, "1-ff00:0:2", 0,
				},
			},
			expected: [][]any{
				{
					0, "1-ff00:0:1", 1,
					nil,
				},
			},
			flyoverDB: [][]any{
				{0, "1-ff00:0:1", 1},
				{0, "1-ff00:0:2", 1},
				{0, "1-ff00:0:3", 1},
			},
		},
		"onepath_twoflyovers": {
			scionPaths: [][]any{
				{
					0, "1-ff00:0:1", 1,
					2, "1-ff00:0:2", 3,
					4, "1-ff00:0:3", 0,
				},
			},
			expected: [][]any{
				{
					0, "1-ff00:0:1", 1,
					2, "1-ff00:0:2", 3,
					nil,
				},
			},
			flyoverDB: [][]any{
				{0, "1-ff00:0:1", 1},
				{2, "1-ff00:0:2", 3},
				{0, "1-ff00:0:2", 1},
				{0, "1-ff00:0:3", 1},
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deadline, _ := t.Deadline()
			ctx, cancelF := context.WithDeadline(context.Background(), deadline)
			defer cancelF()

			flyoverDB := make([]*hummingbird.Flyover, len(tc.flyoverDB))
			for i, flyoverDesc := range tc.flyoverDB {
				flyover := getMockFlyovers(t, flyoverDesc...)
				require.Len(t, flyover, 1, "bad test")
				flyoverDB[i] = flyover[0]
			}
			mockHbirdServer := &mockServer{
				Flyovers: flyoverDB,
			}
			s := &DaemonServer{
				FlyoverDB: mockHbirdServer,
			}
			scionPaths := getMockScionPaths(t, tc.scionPaths)
			rsvs, err := s.getReservations(ctx, scionPaths, util.SecsToTime(currUnixTimestamp), 0)
			require.NoError(t, err)

			// Check the size.
			require.Len(t, rsvs, len(scionPaths))

			// For each path, check the flyovers.
			for i, pRaw := range scionPaths {
				// Decode pRaw into a SCION decoded path.
				require.IsType(t, path.SCION{}, pRaw.DataplanePath)
				dpRaw := pRaw.DataplanePath.(path.SCION)

				p := scion.Decoded{}
				err := p.DecodeFromBytes(dpRaw.Raw)
				require.NoError(t, err)

				// Same hop count in both SCION path and reservation.
				r := rsvs[i]
				flyoverSequence := r.FlyoverPerHopField()
				require.Equal(t, len(p.HopFields), len(flyoverSequence))

				// Check the flyover sequence.
				expected := getMockFlyovers(t, tc.expected[i]...)
				require.Equal(t, expected, flyoverSequence)
			}
		})
	}
}

func TestStoreFlyovers(t *testing.T) {
	deadline, _ := t.Deadline()
	ctx, cancelF := context.WithDeadline(context.Background(), deadline)
	defer cancelF()

	mockHbirdServer := &mockServer{
		Flyovers: nil, // empty
	}
	s := &DaemonServer{
		FlyoverDB: mockHbirdServer,
	}

	expected := []*hummingbird.Flyover{
		{
			BaseHop: hummingbird.BaseHop{
				IA:      xtest.MustParseIA("1-ff00:0:333"),
				Ingress: 3,
				Egress:  2,
			},
			ResID:     40,
			Bw:        3,
			StartTime: 10,
			Duration:  60,
			Ak:        [16]byte{3, 4, 5, 6},
		},
		{ // same as previous one, not unique (IA,resID)
			BaseHop: hummingbird.BaseHop{
				IA:      xtest.MustParseIA("1-ff00:0:333"),
				Ingress: 3,
				Egress:  2,
			},
			ResID:     40,
			Bw:        3,
			StartTime: 10,
			Duration:  60,
			Ak:        [16]byte{3, 4, 5, 6},
		},
		{
			BaseHop: hummingbird.BaseHop{
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Ingress: 1,
				Egress:  2,
			},
			ResID:     40,
			Bw:        3,
			StartTime: 10,
			Duration:  60,
			Ak:        [16]byte{3, 4, 5, 6},
		},
	}
	req := &sdpb.StoreFlyoversRequest{
		Flyovers: hummingbird.ConvertFlyoversToPB(expected),
	}
	_, err := s.StoreFlyovers(ctx, req)
	require.NoError(t, err)

	// Check DB.
	require.EqualValues(t, expected, mockHbirdServer.Flyovers)
}

func TestListFlyovers(t *testing.T) {
	deadline, _ := t.Deadline()
	ctx, cancelF := context.WithDeadline(context.Background(), deadline)
	defer cancelF()

	expected := []*hummingbird.Flyover{
		{
			BaseHop: hummingbird.BaseHop{
				IA:      xtest.MustParseIA("1-ff00:0:333"),
				Ingress: 3,
				Egress:  2,
			},
			ResID:     40,
			Bw:        3,
			StartTime: 10,
			Duration:  60,
			Ak:        [16]byte{3, 4, 5, 6},
		},
		{
			BaseHop: hummingbird.BaseHop{
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Ingress: 1,
				Egress:  2,
			},
			ResID:     40,
			Bw:        3,
			StartTime: 10,
			Duration:  60,
			Ak:        [16]byte{3, 4, 5, 6},
		},
	}

	mockHbirdServer := &mockServer{
		Flyovers: expected,
	}
	s := &DaemonServer{
		FlyoverDB: mockHbirdServer,
	}

	req := &sdpb.ListFlyoversRequest{}
	res, err := s.ListFlyovers(ctx, req)
	require.NoError(t, err)

	// Check response.
	require.EqualValues(t, expected, hummingbird.ConvertFlyoversFromPB(res.Flyovers))
}

func getMockScionPaths(t require.TestingT, paths [][]any) []path.Path {
	ret := make([]path.Path, len(paths))
	for i, p := range paths {
		ret[i] = getMockScionPath(t, p...)
	}
	return ret
}

// getMockScionPath returns a snet.path.Path that resembles a SCION path, with appropriate
// metadata included.
// The parameter `hops` must be of the form (0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0) to indicate
// one hop between those two ASes. For more ASes, add more hops in the middle.
// First and last interface IDs must always be 0.
func getMockScionPath(t require.TestingT, hops ...any) path.Path {
	// Check the arguments.
	require.Equal(t, 0, len(hops)%3, "invalid hops field")
	require.Equal(t, 0, hops[0].(int))
	require.Equal(t, 0, hops[len(hops)-1].(int))

	// Parse hops argument.
	hopFields := make([]pathlayers.HopField, len(hops)/3)
	// interfaces has src and dst as extra. Will have to remove first and last items.
	interfaces := make([]snet.PathInterface, len(hops)/3*2)
	for i := 0; i < len(hops); i += 3 {
		require.IsType(t, 0, hops[i])    // check is int
		require.IsType(t, "", hops[i+1]) // check is string
		require.IsType(t, 0, hops[i+2])  // check is int

		ia := xtest.MustParseIA(hops[i+1].(string))
		in := hops[i].(int)
		eg := hops[i+2].(int)

		// Set the values for this hop.
		hopFields[i/3].ConsIngress = uint16(in)
		hopFields[i/3].ConsEgress = uint16(eg)
		hopFields[i/3].ExpTime = currUnixTimestamp + 100
		hopFields[i/3].Mac = [6]byte{1, 2, 3, 4, 5, 6}

		// Set the values for the ingress and the egress interfaces for the metadata field.
		interfaces[i/3*2].IA = ia
		interfaces[i/3*2].ID = common.IFIDType(in)
		interfaces[i/3*2+1].IA = ia
		interfaces[i/3*2+1].ID = common.IFIDType(eg)
	}

	// Build a SCION decoded path.
	scionPath := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{uint8(len(hops) / 3), 0, 0},
			},
			NumINF:  1,
			NumHops: len(hopFields),
		},
		InfoFields: []pathlayers.InfoField{
			{
				ConsDir:   true,
				SegID:     1,
				Timestamp: 10,
			},
		},
		HopFields: hopFields,
	}

	// Build a SCION path based on the decoded one.
	raw, err := scionPath.ToRaw()
	require.NoError(t, err)
	return path.Path{
		Src: interfaces[0].IA,
		Dst: interfaces[len(interfaces)-1].IA,
		Meta: snet.PathMetadata{
			// Remove the extra start and end hops.
			Interfaces: interfaces[1 : len(interfaces)-1],
		},
		DataplanePath: path.SCION{
			Raw: raw.Raw,
		},
	}
}

// getMockFlyovers receives a []any like {0, "1-ff00:0:1", 1} and creates a flyover
// using those values.
func getMockFlyovers(t require.TestingT, hops ...any) []*hummingbird.Flyover {
	// Parse hops argument.
	flyovers := make([]*hummingbird.Flyover, 0)
	for i := 0; i < len(hops); i++ {
		var f *hummingbird.Flyover
		if hops[i] != nil {
			in := hops[i].(int)
			ia := xtest.MustParseIA(hops[i+1].(string))
			eg := hops[i+2].(int)
			f = &hummingbird.Flyover{
				BaseHop: hummingbird.BaseHop{
					IA:      ia,
					Ingress: uint16(in),
					Egress:  uint16(eg),
				},
				StartTime: currUnixTimestamp,
				Duration:  100,
			}
			i += 2 // advance faster
		}
		// Append a new flyover or nil.
		flyovers = append(flyovers, f)
	}
	return flyovers
}

type mockServer struct {
	Flyovers []*hummingbird.Flyover
}

func (m *mockServer) BeginTransaction(ctx context.Context, opts *sql.TxOptions,
) (hummingbirddb.Transaction, error) {
	panic("not implemented")
}

func (m *mockServer) GetFlyovers(
	ctx context.Context,
	owners []addr.IA,
) ([]*hummingbird.Flyover, error) {

	if len(owners) == 0 {
		return m.Flyovers, nil
	}

	// Create a set of the requested IAs.
	ownerMap := make(map[addr.IA]struct{})
	for _, o := range owners {
		ownerMap[o] = struct{}{}
	}

	// Find any flyover with any such IA and return it.
	ret := make([]*hummingbird.Flyover, 0)
	for _, f := range m.Flyovers {
		if _, ok := ownerMap[f.IA]; ok {
			ret = append(ret, f)
		}
	}
	return ret, nil
}

func (m *mockServer) StoreFlyovers(ctx context.Context, flyovers []*hummingbird.Flyover) error {
	m.Flyovers = append(m.Flyovers, flyovers...)
	return nil
}

func (m *mockServer) DeleteExpiredFlyovers(ctx context.Context) (int, error) {
	panic("not implemented")
}
