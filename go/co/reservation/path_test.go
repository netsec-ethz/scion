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

	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestTransparentToRawFromRaw(t *testing.T) {
	cases := map[string]struct {
		transp *TransparentPath
	}{
		"nil": {
			transp: nil,
		},
		"empty": {
			transp: &TransparentPath{
				CurrentStep: 0,
				Steps:       []PathStep{},
			},
		},
		"no raw path": {
			transp: &TransparentPath{
				CurrentStep: 1,
				Steps: []PathStep{
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
		},
		"some raw path": {
			transp: &TransparentPath{
				CurrentStep: 1,
				Steps: []PathStep{
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
				RawPath: MustParseColibriPath("000000000000000000000003" +
					"0123456789ab0123456789ab000000000d00000000000001" +
					"0123456700010002012345670001000001234567"),
			},
		},
		"only raw path": {
			transp: &TransparentPath{
				CurrentStep: 111,
				Steps:       []PathStep{},
				RawPath: MustParseColibriPath("000000000000000000000003" +
					"0123456789ab0123456789ab000000000d00000000000001" +
					"0123456700010002012345670001000001234567"),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := tc.transp.ToRaw()
			transp, err := TransparentPathFromRaw(raw)
			require.NoError(t, err, "buffer=%s", hex.EncodeToString(raw))
			require.Equal(t, tc.transp, transp, "buffer=%s", hex.EncodeToString(raw))
		})
	}
}

func TestReverse(t *testing.T) {
	// TODO(juagargi) use go/co/reservation/test.NewPath for the tests
	cases := map[string]struct {
		original    *TransparentPath
		reversed    *TransparentPath
		expectedErr bool
	}{
		"nil": {
			original: nil,
			reversed: nil,
		},
		"two_steps": {
			original: &TransparentPath{
				CurrentStep: 1,
				Steps: []PathStep{
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
			reversed: &TransparentPath{
				CurrentStep: 0,
				Steps: []PathStep{
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
		},
		"two_steps_with_raw_path": {
			original: &TransparentPath{
				CurrentStep: 1,
				Steps: []PathStep{
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
				RawPath: MustParseColibriPath("000000000000000000000003" +
					"0123456789ab0123456789ab000000000d00000000000001" +
					"0123456700010002012345670001000001234567"),
			},
			reversed: &TransparentPath{
				CurrentStep: 0,
				Steps: []PathStep{
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
				RawPath: MustParseColibriPath("000000000000000040000203" +
					"0123456789ab0123456789ab000000000d00000000010000" +
					"0123456700010002012345670000000101234567"),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.original.Reverse()
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.reversed, tc.original)
			}
		})
	}
}

func TestTransparentPathFromSnet(t *testing.T) {
	cases := map[string]struct {
		snetPath    snet.Path
		expected    *TransparentPath
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
			expected: &TransparentPath{
				CurrentStep: 0,
				Steps: []PathStep{
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
				RawPath: MustParseColibriPath("000000000000000080000003" +
					"0123456789ab0123456789ab000000000d00000000000001" +
					"0123456700010002012345670001000001234567"),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tp, err := TransparentPathFromSnet(tc.snetPath)

			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, tp)
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
