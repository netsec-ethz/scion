// Copyright 2020 ETH Zurich, Anapaya Systems
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

package conf

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestReservationsJson(t *testing.T) {
	cases := map[string]struct {
		filename string
		rsvs     Reservations
	}{
		"one reservation": {
			filename: "one_reservation.json",
			rsvs: Reservations{
				Rsvs: []ReservationEntry{
					{
						DstAS:         xtest.MustParseIA("1-ff00:1:112"),
						PathType:      reservation.DownPath,
						PathPredicate: "1-ff00:1:112#0",
						MaxSize:       13,
						MinSize:       7,
						SplitCls:      7,
						EndProps: EndProps(reservation.NewPathEndProps(true, true,
							true, true)),
					},
				},
			},
		},
		"two reservations": {
			filename: "two_reservations.json",
			rsvs: Reservations{
				Rsvs: []ReservationEntry{
					{
						DstAS:         xtest.MustParseIA("1-ff00:1:112"),
						PathType:      reservation.DownPath,
						PathPredicate: "1-ff00:1:112#0",
						MaxSize:       13,
						MinSize:       7,
						SplitCls:      7,
						EndProps: EndProps(reservation.NewPathEndProps(false, false,
							false, false)),
					},
					{
						DstAS:         xtest.MustParseIA("1-ff00:1:113"),
						PathType:      reservation.UpPath,
						PathPredicate: "1-ff00:1:113#0",
						MaxSize:       13,
						MinSize:       7,
						SplitCls:      7,
						EndProps: EndProps(reservation.NewPathEndProps(false, true,
							true, false)),
					},
				},
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			buf, err := json.MarshalIndent(tc.rsvs, "", "  ")
			buf = append(buf, '\n')
			require.NoError(t, err)
			expectedJSON := xtest.MustReadFromFile(t, tc.filename)
			require.Equal(t, expectedJSON, buf, "serialized failed.\nexpected: %s\nactual: %s",
				string(expectedJSON), string(buf))
			// parse back the json and compare to memory struct:
			rsvs := &Reservations{}
			err = json.Unmarshal(expectedJSON, &rsvs)
			require.NoError(t, err)
			require.Equal(t, tc.rsvs, *rsvs)
			// fully construct from file and compare to memory struct:
			rsvs, err = ReservationsFromFile(filepath.Join("testdata", tc.filename))
			require.NoError(t, err)
			require.Equal(t, tc.rsvs, *rsvs)
		})
	}
}
