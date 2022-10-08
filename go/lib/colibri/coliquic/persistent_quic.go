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

package coliquic

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	slayerspath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
)

// PersistentQUIC implements a net.Conn via QUIC.
// It is intended to be used with gRPC by means of its Dial function.
// Only one instance of PersistentQUIC should be created, then its method
// Dialer called to return its dial function, which should be used with grpc.Dial by
// means of WithContextDialer.
//
// gRPC doesn't have support for QUIC yet, and uses HTTP/2 as transport.
// Creating a new grpc.ClientConn doesn't require a new QUIC session, but currently our
// squic.ConnDialer always creates one, which is expensive.
// With PersistQUIC, a new session is created if the object doesn't have one for the
// requested path.
// If it has one, a new stream is created instead.
type PersistentQUIC struct {
	pconn      net.PacketConn
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	sessionsMu sync.Mutex
	sessions   map[string]quic.Session // active session per dst address
	opened     []quic.Session          // all sessions ever opened
}

func NewPersistentQUIC(pconn net.PacketConn, tlsConfig *tls.Config,
	quicConfig *quic.Config) *PersistentQUIC {

	return &PersistentQUIC{
		pconn:      pconn,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		sessionsMu: sync.Mutex{},
		sessions:   make(map[string]quic.Session),
		opened:     make([]quic.Session, 0),
	}
}

// Dial reuses an existing quic session for the path in the destination address, or creates a
// new one. With the session, it opens a new stream that behaves like a net.Conn.
func (pq *PersistentQUIC) Dial(ctx context.Context, dst net.Addr) (net.Conn, error) {
	repr, err := addrToString(dst)
	if err != nil {
		return nil, err
	}
	var sessionError error
	pq.sessionsMu.Lock()
	defer pq.sessionsMu.Unlock()
	for attempts := 0; attempts < 2; attempts++ {
		sess, err := pq.obtainSession(ctx, dst, repr)
		if err != nil {
			sessionError = err
			break
		}
		stream, err := sess.OpenStream()
		if err == nil {
			return streamAsConn{
				stream:  stream,
				session: sess,
			}, nil
		}
		sessionError = err
		var appErr *quic.ApplicationError
		var netErr net.Error
		switch {
		case errors.As(err, &appErr) && appErr.Remote:
			log.Debug("persistent quic client, session closed at other end", "err", err)
		case errors.As(err, &netErr):
			switch {
			case netErr.Temporary():
				log.Debug("persistent quic, too many streams", "err", err)
			case netErr.Timeout():
				// usual condition, don't log anything
			}
		default:
			return nil, err
		}
		delete(pq.sessions, repr)
	}
	return nil, serrors.New("could not reuse or create a session", "err", sessionError)
}

func (q *PersistentQUIC) Close() error {
	q.sessionsMu.Lock()
	defer q.sessionsMu.Unlock()
	errs := serrors.List{}
	for _, s := range q.opened {
		if err := s.CloseWithError(0, ""); err != nil {
			errs = append(errs, err)
		}
	}
	return errs.ToError()
}

func (pq *PersistentQUIC) obtainSession(ctx context.Context, addr net.Addr, repr string) (
	quic.Session, error) {

	sess, ok := pq.sessions[repr]
	if !ok {
		var err error
		sess, err = quic.DialContext(ctx, pq.pconn, addr, addrToSNI(addr),
			pq.tlsConfig, pq.quicConfig)
		if err != nil {
			return nil, err
		}
		pq.sessions[repr] = sess
		pq.opened = append(pq.opened, sess)
	}
	return sess, nil
}

// streamAsConn is a net.Conn backed by a quic stream.
type streamAsConn struct {
	stream  quic.Stream
	session quic.Session // only used for the local and remote addresses.
}

func (c streamAsConn) Read(b []byte) (int, error) {
	n, err := c.stream.Read(b)
	var appErr *quic.ApplicationError
	if err != nil && errors.As(err, &appErr) && appErr.ErrorCode == 0 {
		return 0, io.EOF
	}
	return n, err
}

func (c streamAsConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c streamAsConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c streamAsConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c streamAsConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c streamAsConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c streamAsConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c streamAsConn) Context() context.Context {
	return c.stream.Context()
}

func (c streamAsConn) Close() error {
	return c.stream.Close()
}

// addrToString returns a string representation of the address.
func addrToString(addr net.Addr) (string, error) {
	switch addr := addr.(type) {
	case *snet.UDPAddr:
		return snetAddrToString(addr)
	default:
		return addr.String(), nil // e.g. 10.1.2.3:12345
	}
}

// snetAddrToString returns a string representation of the address/path tuple passed as argument.
// The representation is invariant to e.g. packet size and precision timestamps.
func snetAddrToString(addr *snet.UDPAddr) (string, error) {
	switch p := addr.Path.(type) {
	case path.Empty:
		return addrPathToString(addr, empty.PathType, nil), nil
	case path.SCION:
		return addrPathToString(addr, scion.PathType, p.Raw), nil
	case path.OneHop:
		var buff [slayerspath.InfoLen + 2*slayerspath.HopLen]byte
		if err := p.Info.SerializeTo(buff[:]); err != nil {
			return "", err
		}
		if err := p.FirstHop.SerializeTo(buff[slayerspath.InfoLen:]); err != nil {
			return "", err
		}
		if err := p.FirstHop.SerializeTo(buff[slayerspath.InfoLen+slayerspath.HopLen:]); err !=
			nil {
			return "", err
		}
		return addrPathToString(addr, onehop.PathType, buff[:]), nil
	case path.Colibri:
		return addrPathToString(addr, colibri.PathType, p.Raw), nil
	case snet.RawPath:
		return addrPathToString(addr, p.PathType, p.Raw), nil
	case snet.RawReplyPath:
		buff := make([]byte, p.Path.Len())
		if err := p.Path.SerializeTo(buff); err != nil {
			return "", err
		}
		return addrPathToString(addr, p.Path.Type(), buff), nil
	default:
		return "", serrors.New("unknown dataplane path", "type", common.TypeOf(p))
	}
}

// addrPathToString returns a canonical representation of the address and path, which is
// invariant against the packet size and precision timestamp (COLIBRI)
func addrPathToString(addr *snet.UDPAddr, pt slayerspath.Type, raw []byte) string {
	var suffix string
	switch pt {
	case empty.PathType:
	case colibri.PathType:
		suffix = hex.EncodeToString(invariantColibri(raw))
	default:
		suffix = hex.EncodeToString(raw)
	}
	suffix += addr.String()
	return pt.String() + suffix
}

// addrToSNI returns the server name indication for an address.
func addrToSNI(addr net.Addr) string {
	switch addr := addr.(type) {
	case *snet.UDPAddr:
		return fmt.Sprintf("[%s]:%d", addr.Host.IP, addr.Host.Port)
	default:
		return addr.String()
	}
}

// invariantColibri sets the timestamp and the packet length of the argument to zero.
// The argument should be a serialized colibri path (but this is not checked).
func invariantColibri(buff []byte) []byte {
	raw := append([]byte{}, buff...)
	if len(buff) >= 8+colibri.LenInfoField {
		copy(raw[0:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
		copy(raw[8+22:8+22+2], []byte{0, 0})
	}
	return raw
}
