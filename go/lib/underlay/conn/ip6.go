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

//go:build go1.9 && linux
// +build go1.9,linux

// Package conn implements underlay sockets.
package conn

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/go/lib/sockctrl"
)

type connUDPIPv6 struct {
	connUDPBase
	pconn *ipv6.PacketConn
}

func newConnUDPIPv6(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv6, error) {
	cc := &connUDPIPv6{}
	cc.connUDPBase.ipProtoHandler = cc
	if err := cc.initConnUDP("udp6", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv6.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv6) ReadBatch(msgs Messages) (int, error) {
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	return n, err
}

func (c *connUDPIPv6) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv6) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv6) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv6) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

func (c *connUDPIPv6) SetSocketOptions(so *net.UDPConn) error {
	return sockctrl.SetsockoptInt(so, syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
}

func (c *connUDPIPv6) BuildAddress(sa syscall.Sockaddr) *net.UDPAddr {
	sa6 := sa.(*syscall.SockaddrInet6)
	return &net.UDPAddr{IP: sa6.Addr[0:], Port: sa6.Port, Zone: net.IPAddr{}.Zone}
}

func (c *connUDPIPv6) GetDstAddress(msgs []syscall.SocketControlMessage) (net.IP, error) {
	var dstAddr net.IP
	for _, msg := range msgs {
		if msg.Header.Level == syscall.IPPROTO_IPV6 && msg.Header.Type == syscall.IPV6_PKTINFO {
			info := &syscall.Inet6Pktinfo{}
			if err := binary.Read(bytes.NewReader(msg.Data), binary.BigEndian, info); err != nil {
				return nil, err
			}
			dstAddr = info.Addr[:]
		}
	}
	return dstAddr, nil
}
