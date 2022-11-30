// Copyright 2022 ETH Zurich
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

package addr

import (
	"net"
	"testing"

	"github.com/scionproto/scion/go/lib/slayers/scion"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/stretchr/testify/require"
)

func TestNewEndpoint(t *testing.T) {
	cases := map[string]struct {
		ia       string
		addr     net.Addr
		expected Endpoint
	}{
		"ipv4": {
			ia:   "1-ff00:0:111",
			addr: xtest.MustParseIPAddr(t, "", "1.1.1.1"),
			expected: Endpoint{
				host:     xtest.MustParseIP(t, "1.1.1.1").To4(),
				hostType: scion.T4Ip,
				hostLen:  scion.AddrLen4,
			},
		},
		"ipv6": {
			ia:   "1-ff00:0:111",
			addr: xtest.MustParseIPAddr(t, "", "::1"),
			expected: Endpoint{
				host:     xtest.MustParseIP(t, "::1").To16(),
				hostType: scion.T16Ip,
				hostLen:  scion.AddrLen16,
			},
		},
		"udpv4": {
			ia:   "1-ff00:0:113",
			addr: xtest.MustParseUDPAddr(t, "1.1.1.1:80"),
			expected: Endpoint{
				host:     xtest.MustParseIP(t, "1.1.1.1").To4(),
				hostType: scion.T4Ip,
				hostLen:  scion.AddrLen4,
			},
		},
		"udpv6": {
			ia:   "1-ff00:0:110",
			addr: xtest.MustParseUDPAddr(t, "[::1]:80"),
			expected: Endpoint{
				host:     xtest.MustParseIP(t, "::1").To16(),
				hostType: scion.T16Ip,
				hostLen:  scion.AddrLen16,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ia := xtest.MustParseIA(tc.ia)
			tc.expected.IA = ia // always set it as the expected IA
			got := NewEndpointWithAddr(ia, tc.addr)
			require.Equal(t, tc.expected, *got)
		})
	}
}
