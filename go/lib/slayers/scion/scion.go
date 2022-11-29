// Copyright 2022 ETH Zurich, Anapaya Systems
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
	"encoding/binary"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
)

// AddrLen indicates the length of a host address in the SCION header. The four possible lengths are
// 4, 8, 12, or 16 bytes.
type AddrLen uint8

// AddrLen constants
const (
	AddrLen4 AddrLen = iota
	AddrLen8
	AddrLen12
	AddrLen16
)

// AddrType indicates the type of a host address of a given length in the SCION header. There are
// four possible types per address length.
type AddrType uint8

// AddrType constants
const (
	T4Ip AddrType = iota
	T4Svc
)

// AddrLen16 types
const (
	T16Ip AddrType = iota
)

// SCION is the header of a SCION packet.
type SCION struct {
	// BaseLayer
	// Common Header fields

	// Version is version of the SCION Header. Currently, only 0 is supported.
	Version uint8
	// TrafficClass denotes the traffic class. Its value in a received packet or fragment might be
	// different from the value sent by the packet’s source. The current use of the Traffic Class
	// field for Differentiated Services and Explicit Congestion Notification is specified in
	// RFC2474 and RFC3168
	TrafficClass uint8
	// FlowID is a 20-bit field used by a source to label sequences of packets to be treated in the
	// network as a single flow. It is mandatory to be set.
	FlowID uint32
	// NextHdr  encodes the type of the first header after the SCION header. This can be either a
	// SCION extension or a layer-4 protocol such as TCP or UDP. Values of this field respect and
	// extend IANA’s assigned internet protocol numbers.
	NextHdr common.L4ProtocolType
	// HdrLen is the length of the SCION header in multiples of 4 bytes. The SCION header length is
	// computed as HdrLen * 4 bytes. The 8 bits of the HdrLen field limit the SCION header to a
	// maximum of 1024 bytes.
	HdrLen uint8
	// PayloadLen is the length of the payload in bytes. The payload includes extension headers and
	// the L4 payload. This field is 16 bits long, supporting a maximum payload size of 64KB.
	PayloadLen uint16
	// PathType specifies the type of path in this SCION header.
	PathType path.Type
	// DstAddrType (2 bit) is the type of the destination address.
	DstAddrType AddrType
	// DstAddrLen (2 bit) is the length of the destination address. Supported address length are 4B
	// (0), 8B (1), 12B (2), and 16B (3).
	DstAddrLen AddrLen
	// SrcAddrType (2 bit) is the type of the source address.
	SrcAddrType AddrType
	// SrcAddrLen (2 bit) is the length of the source address. Supported address length are 4B (0),
	// 8B (1), 12B (2), and 16B (3).
	SrcAddrLen AddrLen

	// Address header fields.

	// DstIA is the destination ISD-AS.
	DstIA addr.IA
	// SrcIA is the source ISD-AS.
	SrcIA addr.IA
	// RawDstAddr is the destination address.
	RawDstAddr []byte
	// RawSrcAddr is the source address.
	RawSrcAddr []byte
}

// DstAddr parses the destination address into a net.Addr. The returned net.Addr references data
// from the underlaying layer data. Changing the net.Addr object might lead to inconsistent layer
// information and thus should be treated read-only. Instead, SetDstAddr should be used to update
// the destination address.
func (s *SCION) DstAddr() (net.Addr, error) {
	return parseAddr(s.DstAddrType, s.DstAddrLen, s.RawDstAddr)
}

// SrcAddr parses the source address into a net.Addr. The returned net.Addr references data from the
// underlaying layer data. Changing the net.Addr object might lead to inconsistent layer information
// and thus should be treated read-only. Instead, SetDstAddr should be used to update the source
// address.
func (s *SCION) SrcAddr() (net.Addr, error) {
	return parseAddr(s.SrcAddrType, s.SrcAddrLen, s.RawSrcAddr)
}

// SetDstAddr sets the destination address and updates the DstAddrLen/Type fields accordingly.
// SetDstAddr takes ownership of dst and callers should not write to it after calling SetDstAddr.
// Changes to dst might leave the layer in an inconsistent state.
func (s *SCION) SetDstAddr(dst net.Addr) error {
	var err error
	s.DstAddrLen, s.DstAddrType, s.RawDstAddr, err = packAddr(dst)
	return err
}

// SetSrcAddr sets the source address and updates the DstAddrLen/Type fields accordingly.
// SetSrcAddr takes ownership of src and callers should not write to it after calling SetSrcAddr.
// Changes to src might leave the layer in an inconsistent state.
func (s *SCION) SetSrcAddr(src net.Addr) error {
	var err error
	s.SrcAddrLen, s.SrcAddrType, s.RawSrcAddr, err = packAddr(src)
	return err
}

func parseAddr(addrType AddrType, addrLen AddrLen, raw []byte) (net.Addr, error) {
	switch addrLen {
	case AddrLen4:
		switch addrType {
		case T4Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		case T4Svc:
			return addr.HostSVC(binary.BigEndian.Uint16(raw[:addr.HostLenSVC])), nil
		}
	case AddrLen16:
		switch addrType {
		case T16Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		}
	}
	return nil, serrors.New("unsupported address type/length combination",
		"type", addrType, "len", addrLen)
}

func packAddr(hostAddr net.Addr) (AddrLen, AddrType, []byte, error) {
	switch a := hostAddr.(type) {
	case *net.IPAddr:
		if ip := a.IP.To4(); ip != nil {
			return AddrLen4, T4Ip, ip, nil
		}
		return AddrLen16, T16Ip, a.IP, nil
	case addr.HostSVC:
		return AddrLen4, T4Svc, a.PackWithPad(2), nil
	}
	return 0, 0, nil, serrors.New("unsupported address", "addr", hostAddr)
}
