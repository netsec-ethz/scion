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
	"encoding/binary"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

// Colibri is a fully specified address for COLIBRI. It requires a source (IA only if SegR),
// a destination (also IA only if SegR), and a COLIBRI path.
type Colibri struct {
	Path colpath.ColibriPathMinimal
	Src  Endpoint
	Dst  Endpoint
}

func (c *Colibri) String() string {
	if c == nil {
		return "(nil)"
	}
	ID := reservation.ID{
		ASID:   c.Src.IA.AS(),
		Suffix: c.Path.InfoField.ResIdSuffix,
	}
	inf := c.Path.InfoField
	return fmt.Sprintf("%s -> %s [ID: %s,Idx: %d] (#HFs:%d,CurrHF:%d,S:%v C:%v R:%v)",
		c.Src, c.Dst, ID, inf.Ver, inf.HFCount, inf.CurrHF, inf.S, inf.C, inf.R)
}

// Endpoint represents one sender or receiver as seen in the SCiON address header.
type Endpoint struct {
	IA       addr.IA          // IA address
	host     []byte           // host address
	hostType slayers.AddrType // {0, 1, 2, 3}
	hostLen  slayers.AddrLen  // host address length, {0, 1, 2, 3} (4, 8, 12, or 16 bytes).
}

func NewEndpointWithAddr(ia addr.IA, hostAddr net.Addr) *Endpoint {
	switch addr := hostAddr.(type) {
	case addr.HostSVC:
		return &Endpoint{
			IA:       ia,
			host:     addr.PackWithPad(2),
			hostType: slayers.T4Svc,
			hostLen:  slayers.AddrLen4,
		}
	case *net.UDPAddr:
		return NewEndpointWithIP(ia, addr.IP)
	case *net.TCPAddr:
		return NewEndpointWithIP(ia, addr.IP)
	case *net.IPAddr:
		return NewEndpointWithIP(ia, addr.IP)
	case *net.IPNet:
		return NewEndpointWithIP(ia, addr.IP)
	default:
		panic(fmt.Sprintf("unsupported type %T", hostAddr))
	}
}

func NewEndpointWithIP(ia addr.IA, ip net.IP) *Endpoint {
	var host []byte
	var hostType slayers.AddrType
	var hostLen slayers.AddrLen
	if ip4 := ip.To4(); ip4 != nil {
		host, hostType, hostLen = ip4, slayers.T4Ip, slayers.AddrLen4
	} else {
		host, hostType, hostLen = ip.To16(), slayers.T16Ip, slayers.AddrLen16
	}

	return &Endpoint{
		IA:       ia,
		host:     host,
		hostType: hostType,
		hostLen:  hostLen,
	}
}

func NewEndpointWithRaw(ia addr.IA, host []byte, hostType slayers.AddrType,
	hostLen slayers.AddrLen) *Endpoint {

	return &Endpoint{
		IA:       ia,
		host:     host,
		hostType: hostType,
		hostLen:  hostLen,
	}
}

// Addr returns the endpoint as a IA, and host address, constructed from the raw IP, the type,
// and length. The host address could be an IPv4, IPv6, or addr.HostSVC.
func (ep Endpoint) Addr() (addr.IA, net.Addr, error) {
	addr, err := parseAddr(ep.hostType, ep.hostLen, ep.host)
	return ep.IA, addr, err
}

func (ep Endpoint) Raw() (
	ia addr.IA, host []byte, hostType slayers.AddrType, hostLen slayers.AddrLen) {

	return ep.IA, ep.host, ep.hostType, ep.hostLen
}

func (ep Endpoint) String() string {
	var host string
	if ep.hostType == slayers.T4Svc {
		h, err := parseAddr(ep.hostType, ep.hostLen, ep.host)
		if err != nil {
			host = err.Error()
		} else {
			host = h.String()
		}
	} else {
		host = (net.IP(ep.host)).String()
	}
	return fmt.Sprintf("%s,%s", ep.IA, host)
}

// parseAddr takes a host address, type and length and returns the abstract representation derived
// from net.Addr. The accepted types are IPv4, IPv6 and addr.HostSVC.
// The type of net.Addr returned will always be net.IPAddr or addr.HostSVC.
// parseAddr was copied from slayers.
func parseAddr(addrType slayers.AddrType, addrLen slayers.AddrLen, raw []byte) (net.Addr, error) {
	switch addrLen {
	case slayers.AddrLen4:
		switch addrType {
		case slayers.T4Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		case slayers.T4Svc:
			return addr.HostSVC(binary.BigEndian.Uint16(raw[:addr.HostLenSVC])), nil
		}
	case slayers.AddrLen16:
		switch addrType {
		case slayers.T16Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		}
	}
	return nil, serrors.New("unsupported address type/length combination",
		"type", addrType, "len", addrLen)
}

// // assert asserts. deleteme
// func assert(cond bool, params ...interface{}) {
// 	if !cond {
// 		panic("bad assert")
// 	}
// }
