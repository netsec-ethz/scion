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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/scion"
)

// Endpoint represents one sender or receiver as seen in the SCiON address header.
type Endpoint struct {
	IA       addr.IA        // IA address
	host     []byte         // host address
	hostType scion.AddrType // {0, 1, 2, 3}
	hostLen  scion.AddrLen  // host address length, {0, 1, 2, 3} (4, 8, 12, or 16 bytes).
}

func NewEndpointWithAddr(ia addr.IA, hostAddr net.Addr) *Endpoint {
	switch addr := hostAddr.(type) {
	case addr.HostSVC:
		return &Endpoint{
			IA:       ia,
			host:     addr.PackWithPad(2),
			hostType: scion.T4Svc,
			hostLen:  scion.AddrLen4,
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
	var hostType scion.AddrType
	var hostLen scion.AddrLen
	if ip4 := ip.To4(); ip4 != nil {
		host, hostType, hostLen = ip4, scion.T4Ip, scion.AddrLen4
	} else {
		host, hostType, hostLen = ip.To16(), scion.T16Ip, scion.AddrLen16
	}

	return &Endpoint{
		IA:       ia,
		host:     host,
		hostType: hostType,
		hostLen:  hostLen,
	}
}

func NewEndpointWithRaw(ia addr.IA, host []byte, hostType scion.AddrType,
	hostLen scion.AddrLen) *Endpoint {

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

func (ep *Endpoint) Raw() (
	ia addr.IA, host []byte, hostType scion.AddrType, hostLen scion.AddrLen) {

	if ep == nil {
		return 0, nil, 0, 0
	}
	return ep.IA, ep.host, ep.hostType, ep.hostLen
}

func (ep Endpoint) String() string {
	var host string
	if ep.hostType == scion.T4Svc {
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

func (ep *Endpoint) Len() uint8 {
	if ep == nil {
		return 1
	}
	// length itself + IA, host len and type + host address
	return 1 + 10 + 4*(uint8(ep.hostLen)+1) //  14, 18, 22 or 26 bytes
}

// SerializeTo serializes the Endpoint to an array of bytes. Format:
// length_in_bytes 				IA	host_len  	host_type  	host_addr
// Examples:
// (empty):      0
// (IPv4):		14	ff00:0001:0110	0			T4Ip		0x7f000001
func (ep *Endpoint) SerializeTo(buff []byte) {
	buff[0] = ep.Len() - 1
	if ep == nil {
		return
	}
	binary.BigEndian.PutUint64(buff[1:], uint64(ep.IA))
	buff[9] = byte(ep.hostLen)
	buff[10] = byte(ep.hostType)
	copy(buff[11:], ep.host)
}

func NewEndpointFromSerialized(buff []byte) *Endpoint {
	if buff[0] == 0 {
		return nil
	}
	// we could assert that the types are valid (in range) but YOLO (actually there is no
	// unsanitized input here, all comes from the SCION header).
	ep := &Endpoint{}
	ep.IA = addr.IA(binary.BigEndian.Uint64(buff[1:]))
	ep.hostLen = scion.AddrLen(buff[9])
	ep.hostType = scion.AddrType(buff[10])
	ep.host = make([]byte, (ep.hostLen+1)*4)
	copy(ep.host, buff[11:11+len(ep.host)])
	return ep
}

// parseAddr takes a host address, type and length and returns the abstract representation derived
// from net.Addr. The accepted types are IPv4, IPv6 and addr.HostSVC.
// The type of net.Addr returned will always be net.IPAddr or addr.HostSVC.
// parseAddr was copied from slayers.
func parseAddr(addrType scion.AddrType, addrLen scion.AddrLen, raw []byte) (net.Addr, error) {
	switch addrLen {
	case scion.AddrLen4:
		switch addrType {
		case scion.T4Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		case scion.T4Svc:
			return addr.HostSVC(binary.BigEndian.Uint16(raw[:addr.HostLenSVC])), nil
		}
	case scion.AddrLen16:
		switch addrType {
		case scion.T16Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		}
	}
	return nil, serrors.New("unsupported address type/length combination",
		"type", addrType, "len", addrLen)
}
