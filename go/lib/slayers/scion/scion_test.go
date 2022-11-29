// Copyright 2022 Anapaya Systems, ETH Zurich
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

package scion

import (
	"net"
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/stretchr/testify/assert"
)

var (
	ip6Addr = &net.IPAddr{IP: net.ParseIP("2001:db8::68")}
	ip4Addr = &net.IPAddr{IP: net.ParseIP("10.0.0.100")}
	svcAddr = addr.HostSVCFromString("Wildcard")
)

func TestPackAddr(t *testing.T) {
	testCases := map[string]struct {
		addr      net.Addr
		addrType  AddrType
		addrLen   AddrLen
		rawAddr   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		"pack IPv4": {
			addr:      ip4Addr,
			addrType:  T4Ip,
			addrLen:   AddrLen4,
			rawAddr:   []byte(ip4Addr.IP.To4()),
			errorFunc: assert.NoError,
		},
		"pack IPv6": {
			addr:      ip6Addr,
			addrType:  T16Ip,
			addrLen:   AddrLen16,
			rawAddr:   []byte(ip6Addr.IP),
			errorFunc: assert.NoError,
		},
		"pack SVC": {
			addr:      svcAddr,
			addrType:  T4Svc,
			addrLen:   AddrLen4,
			rawAddr:   svcAddr.PackWithPad(2),
			errorFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addrLen, addrType, rawAddr, err := packAddr(tc.addr)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.addrType, addrType)
			assert.Equal(t, tc.addrLen, addrLen)
			assert.Equal(t, tc.rawAddr, rawAddr)
		})
	}
}

func TestParseAddr(t *testing.T) {
	testCases := map[string]struct {
		addrType  AddrType
		addrLen   AddrLen
		rawAddr   []byte
		want      net.Addr
		errorFunc assert.ErrorAssertionFunc
	}{
		"parse IPv4": {
			addrType:  T4Ip,
			addrLen:   AddrLen4,
			rawAddr:   []byte(ip4Addr.IP),
			want:      ip4Addr,
			errorFunc: assert.NoError,
		},
		"parse IPv6": {
			addrType:  T16Ip,
			addrLen:   AddrLen16,
			rawAddr:   []byte(ip6Addr.IP),
			want:      ip6Addr,
			errorFunc: assert.NoError,
		},
		"parse SVC": {
			addrType:  T4Svc,
			addrLen:   AddrLen4,
			rawAddr:   svcAddr.PackWithPad(2),
			want:      svcAddr,
			errorFunc: assert.NoError,
		},
		"parse unknown type": {
			addrType:  0,
			addrLen:   AddrLen8,
			rawAddr:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAddr(tc.addrType, tc.addrLen, tc.rawAddr)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
