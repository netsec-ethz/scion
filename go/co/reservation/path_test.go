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

package reservation

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPathStepsToRawFromRaw(t *testing.T) {
	cases := map[string]struct {
		steps    PathSteps
		expected PathSteps
	}{
		"nil": {
			steps:    nil,
			expected: PathSteps{},
		},
		"empty": {
			steps:    PathSteps{},
			expected: PathSteps{},
		},
		"path": {
			steps: PathSteps{
				{
					Ingress: 0,
					Egress:  1,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
				{
					Ingress: 4,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
			},
			expected: PathSteps{
				{
					Ingress: 0,
					Egress:  1,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
				{
					Ingress: 4,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := tc.steps.ToRaw()
			steps := PathStepsFromRaw(raw)
			require.Equal(t, tc.expected, steps, "buffer=%s", hex.EncodeToString(raw))
		})
	}
}

func TestReverse(t *testing.T) {
	// TODO(juagargi) use go/co/reservation/test.NewPath for the tests
	cases := map[string]struct {
		original PathSteps
		reversed PathSteps
	}{
		"nil": {
			original: nil,
			reversed: PathSteps{},
		},
		"two_steps": {
			original: PathSteps{
				{
					Ingress: 0,
					Egress:  1,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
				{
					Ingress: 4,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
			},
			reversed: PathSteps{
				{
					Ingress: 0,
					Egress:  4,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
				{
					Ingress: 1,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
			},
		},
		"two_steps_with_raw_path": {
			original: PathSteps{
				{
					Ingress: 0,
					Egress:  1,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
				{
					Ingress: 4,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
			},
			reversed: PathSteps{
				{
					Ingress: 0,
					Egress:  4,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
				{
					Ingress: 1,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reversed := tc.original.Reverse()
			require.Equal(t, tc.reversed, reversed)
		})
	}
}

func TestPathStepsValidateEquivalent(t *testing.T) {
	// test topology for all cases:
	//
	//					+---+  1 2   +---+  3 4   +----+  5 7   +---+
	//					| E | -----> | D | -----> | C  | -----> | A |
	//					+---+        +---+        +----+        +---+
	//
	steps_ACD := PathSteps{ // A->C->D    This is one seg. reservation only
		{
			Ingress: 0,
			Egress:  7,
		},
		{
			Ingress: 5,
			Egress:  4,
		},
		{
			Ingress: 3,
			Egress:  0,
		},
	}
	col_ACD_at_1 := &colpath.ColibriPath{ // A->C->D    at C
		InfoField: &colpath.InfoField{
			ResIdSuffix: xtest.MustParseHexString("0123456789abcdef01234567"),
			HFCount:     3,
			CurrHF:      1,
			S:           true,
		},
		HopFields: []*colpath.HopField{
			{
				IngressId: 0,
				EgressId:  7,
				Mac:       xtest.MustParseHexString("01234567"),
			},
			{
				IngressId: 5,
				EgressId:  4,
				Mac:       xtest.MustParseHexString("01234567"),
			},
			{
				IngressId: 3,
				EgressId:  0,
				Mac:       xtest.MustParseHexString("01234567"),
			},
		},
	}
	col2_ACD_at_1 := col_ACD_at_1.Clone()
	cases := map[string]struct {
		expectError bool
		steps       PathSteps
		atStep      int
		path        *colpath.ColibriPath
	}{
		"colibri1": {
			expectError: false,
			steps:       steps_ACD,
			atStep:      1,
			path:        col_ACD_at_1,
		},
		"colibri2": {
			expectError: false,
			steps:       steps_ACD,
			atStep:      1,
			path:        col2_ACD_at_1,
		},
		"colibri_bad_curr_step1": {
			expectError: true,
			steps:       steps_ACD,
			atStep:      2,
			path:        col_ACD_at_1,
		},
		"colibri_bad_curr_step2": {
			expectError: true,
			steps:       steps_ACD,
			atStep:      0,
			path:        col_ACD_at_1,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			minimal, err := tc.path.ToMinimal()
			require.NoError(t, err)
			err = tc.steps.ValidateEquivalent(minimal, tc.atStep)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPathStepsFromSnet(t *testing.T) {
	cases := map[string]struct {
		snetPath    snet.Path
		expected    PathSteps
		expectedErr bool
	}{
		"nil": {
			expected:    nil,
			snetPath:    nil,
			expectedErr: false,
		},
		"colibri_path": {
			snetPath: path.Path{
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							ID: 1,
							IA: xtest.MustParseIA("1-ff00:0:111"),
						},
						{
							ID: 4,
							IA: xtest.MustParseIA("1-ff00:0:110"),
						},
					},
				},
				DataplanePath: path.Colibri{
					ColibriPathMinimal: colpath.ColibriPathMinimal{},
				},
			},
			expected: PathSteps{
				{
					Ingress: 0,
					Egress:  1,
					IA:      xtest.MustParseIA("1-ff00:0:111"),
				},
				{
					Ingress: 4,
					Egress:  0,
					IA:      xtest.MustParseIA("1-ff00:0:110"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			steps, err := StepsFromSnet(tc.snetPath)

			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, steps)
			}
		})
	}
}

func TestColPathToRaw(t *testing.T) {
	cases := map[string]struct {
		Path *colpath.ColibriPath
	}{
		"smallest": {
			Path: &colpath.ColibriPath{
				InfoField: &colpath.InfoField{
					ResIdSuffix: make([]byte, 12),
					HFCount:     2,
				},
				HopFields: []*colpath.HopField{
					{
						Mac: make([]byte, 4),
					},
					{
						Mac: make([]byte, 4),
					},
				},
			},
		},
		"regular": { // is two hop fields
			Path: &colpath.ColibriPath{
				InfoField: &colpath.InfoField{
					ResIdSuffix: make([]byte, 12),
					HFCount:     2,
					R:           true,
					BwCls:       3,
					OrigPayLen:  1000,
					Ver:         1,
					ExpTick:     0xff00ff00,
				},
				HopFields: []*colpath.HopField{
					{
						Mac: make([]byte, 4),
					},
					{
						Mac: make([]byte, 4),
					},
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			minimal, err := tc.Path.ToMinimal()
			require.NoError(t, err)
			// test function
			raw, err := ColPathToRaw(minimal)
			require.NoError(t, err)
			newPath := &colpath.ColibriPathMinimal{}
			err = newPath.DecodeFromBytes(raw)
			require.NoError(t, err)
			require.Equal(t, minimal, newPath)
		})
	}
}
