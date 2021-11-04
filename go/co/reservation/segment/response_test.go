// Copyright 2021 ETH Zurich
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

package segment

import (
	"encoding/hex"
	"fmt"
	"testing"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/stretchr/testify/require"
)

func TestSegmentSetupResponseSuccessToRaw(t *testing.T) {
	cases := map[string]struct {
		res      SegmentSetupResponseSuccess
		step     int
		expected []byte
	}{
		"tiny_topo_111_to_110": {
			res: SegmentSetupResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 1),
				},
				Token: reservation.Token{
					InfoField: reservation.InfoField{
						PathType: reservation.CorePath,
						Idx:      1,
						// ...
					},
					HopFields: []reservation.HopField{
						{ // HF added at 111 (step 0)
							Ingress: 0,
							Egress:  255,
							Mac:     [4]byte{127, 128, 129, 130},
						},
						{ // HF added at 110 (step 1)
							Ingress: 1,
							Egress:  0,
							Mac:     [4]byte{4, 5, 6, 7},
						},
					},
				},
			},
			step: 1,
			// 00 success marker
			// 00000001 timestamp
			// 0000000000001100 info field
			// 0001000004050607 hop field [0]
			expected: xtest.MustParseHexString("000000000100000000000011000001000004050607"),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.res.ToRaw(tc.step)
			require.Equal(t, tc.expected, got, fmt.Sprintf("actual   %s\nexpected %s",
				hex.EncodeToString(got), hex.EncodeToString(tc.expected)))
		})
	}
}
