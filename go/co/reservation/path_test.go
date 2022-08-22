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

	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
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
		"colibri_with_raw_path": {
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
					Raw: xtest.MustParseHexString("000000000000000080000003" +
						"0123456789ab0123456789ab000000000d00000000000001" +
						"0123456700010002012345670001000001234567"),
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

func TestRawFromSnet(t *testing.T) {
	cases := map[string]struct {
		snetPath    snet.Path
		expected    slayerspath.Path
		expectedErr bool
	}{
		"colibri_with_raw_path": {
			snetPath: path.Path{
				DataplanePath: path.Colibri{
					Raw: xtest.MustParseHexString("000000000000000080000003" +
						"0123456789ab0123456789ab000000000d00000000000001" +
						"0123456700010002012345670001000001234567"),
				},
			},
			expected: MustParseColibriPath("000000000000000080000003" +
				"0123456789ab0123456789ab000000000d00000000000001" +
				"0123456700010002012345670001000001234567"),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := PathFromDataplanePath(tc.snetPath.Dataplane())

			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, raw)
			}
		})
	}
}

func MustParseColibriPath(hexString string) *colibri.ColibriPathMinimal {
	buff := xtest.MustParseHexString(hexString)
	p := &colibri.ColibriPathMinimal{}
	err := p.DecodeFromBytes(buff)
	if err != nil {
		panic(err)
	}
	return p
}
