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

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/sockctrl"
)

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv4, error) {
	cc := &connUDPIPv4{}
	cc.connUDPBase.ipProtoHandler = cc
	if err := cc.initConnUDP("udp4", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv4.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs Messages) (int, error) {
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	return n, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv4) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv4) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv4) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

func (c *connUDPIPv4) SetSocketOptions(so *net.UDPConn) error {
	return sockctrl.SetsockoptInt(so, syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
}

func (c *connUDPIPv4) BuildAddress(sa syscall.Sockaddr) *net.UDPAddr {
	sa4 := sa.(*syscall.SockaddrInet4)
	return &net.UDPAddr{IP: sa4.Addr[0:], Port: sa4.Port, Zone: net.IPAddr{}.Zone}
}

func (c *connUDPIPv4) GetDstAddress(msgs []syscall.SocketControlMessage) (net.IP, error) {
	var dstAddr net.IP
	for _, msg := range msgs {
		if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == syscall.IP_PKTINFO {
			info := &syscall.Inet4Pktinfo{}
			if err := binary.Read(bytes.NewReader(msg.Data), binary.BigEndian, info); err != nil {
				return nil, err
			}
			dstAddr = info.Addr[:]
		}
	}
	return dstAddr, nil
}
