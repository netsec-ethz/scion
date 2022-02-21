// Copyright 2021 ETH Zurich
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

// Package coliquic implements QUIC on top of COLIBRI.
// Inspired on squic.
// Test with go test ./go/lib/colibri/coliquic/ -count=1
package coliquic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/xtest"
	sgrpc "github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
	mock_col "github.com/scionproto/scion/go/pkg/proto/colibri/mock_colibri"
)

// TestColibriQuic creates a server and a client, both with SCION-COLIBRI addresses and paths,
// and communicates both via a quic connection.
func TestColibriQuic(t *testing.T) {

	testCases := map[string]struct {
		serverAddr net.Addr
		clientAddr net.Addr
	}{
		"scion": {
			serverAddr: mockScionAddress(t, "1-ff00:0:111",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210, Zone: ""}),
			clientAddr: mockScionAddress(t, "1-ff00:0:112",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345, Zone: ""}),
		},
		"colibri": {
			serverAddr: mockScionAddress(t, "1-ff00:0:111",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43211, Zone: ""}),
			clientAddr: mockColibriAddress(t, "1-ff00:0:112",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346, Zone: ""}),
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // we are not really using sockets -> no bind clashes
			thisNet := newMockNetwork()
			// server:
			serverTlsConfig := &tls.Config{
				Certificates: []tls.Certificate{*createTestCertificate(t)},
				NextProtos:   []string{"coliquictest"},
			}
			serverQuicConfig := &quic.Config{KeepAlive: true}
			listener, err := quic.Listen(newConnMock(t, tc.serverAddr, thisNet),
				serverTlsConfig, serverQuicConfig)
			require.NoError(t, err)

			done := make(chan struct{})
			ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelF()
			go func(ctx context.Context, listener quic.Listener) {
				session, err := listener.Accept(ctx)
				require.NoError(t, err)

				colPath, err := GetColibriPath(session)
				require.NoError(t, err)
				clientPath := tc.clientAddr.(*snet.UDPAddr).Path
				if _, ok := clientPath.(path.Colibri); ok {
					buff := make([]byte, colPath.Len())
					err = colPath.SerializeTo(buff)
					require.NoError(t, err)
					require.Equal(t, clientPath.(path.Colibri).Raw, buff)
				} else {
					require.Nil(t, colPath)
				}

				stream, err := session.AcceptStream(ctx)
				require.NoError(t, err)
				buff := make([]byte, 16384)
				n, err := stream.Read(buff)
				require.NoError(t, err)
				require.Equal(t, "hello world", string(buff[:n]))
				err = stream.Close()
				require.NoError(t, err)
				done <- struct{}{}
			}(ctx, listener)

			// client:
			clientTlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"coliquictest"},
			}
			clientQuicConfig := &quic.Config{KeepAlive: true}

			ctx2, cancelF2 := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF2()
			session, err := quic.DialContext(ctx2, newConnMock(t, tc.clientAddr, thisNet),
				tc.serverAddr, "serverName", clientTlsConfig, clientQuicConfig)
			require.NoError(t, err)
			stream, err := session.OpenStream()
			require.NoError(t, err)
			n, err := stream.Write([]byte("hello world"))
			require.NoError(t, err)
			require.Equal(t, len("hello wold")+1, n)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "timed out")
			}
			err = stream.Close()
			require.NoError(t, err)
		})
	}
}

func TestColibriGRPC(t *testing.T) {
	thisNet := newMockNetwork()

	// server: (don't reuse addresses on any test, as quic caches the connections)
	serverAddr := mockScionAddress(t, "1-ff00:0:111",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23211, Zone: ""})
	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*createTestCertificate(t)},
		NextProtos:   []string{"coliquicgrpc"},
	}
	serverQuicConfig := &quic.Config{KeepAlive: true}

	quicLis, err := quic.Listen(newConnMock(t, serverAddr, thisNet),
		serverTlsConfig, serverQuicConfig)
	require.NoError(t, err)

	listener := NewConnListener(quicLis)
	require.NoError(t, err)

	// mock a method (see net_test) and check we recover the colibri path correctly
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	handler := mock_col.NewMockColibriServiceServer(mctrl)
	// use SetupSegment to check that the client talks to the server as expected,
	// and that the server is able to extract the address and path to the client.
	handler.EXPECT().SegmentSetup(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
		func(ctx context.Context, _ *colpb.SegmentSetupRequest) (
			*colpb.SegmentSetupResponse, error) {

			p, ok := peer.FromContext(ctx)
			require.True(t, ok)
			require.NotNil(t, p)
			require.IsType(t, &snet.UDPAddr{}, p.Addr)
			require.IsType(t, path.Colibri{}, p.Addr.(*snet.UDPAddr).Path)
			ok, usage, err := UsageFromContext(ctx)
			require.NoError(t, err)
			require.True(t, ok)
			require.Greater(t, usage, uint64(0))
			return &colpb.SegmentSetupResponse{SuccessFailure: &colpb.SegmentSetupResponse_Token{
				Token: p.Addr.(*snet.UDPAddr).Path.(path.Colibri).Raw,
			}}, nil
		})

	var testInterceptorCalled bool
	testInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		res, err := handler(ctx, req)
		testInterceptorCalled = true
		return res, err
	}

	gRPCServer := NewGrpcServer(grpc.UnaryInterceptor(testInterceptor),
		sgrpc.UnaryServerInterceptor())
	colpb.RegisterColibriServiceServer(gRPCServer, handler)

	done := make(chan struct{})
	go func() {
		err = gRPCServer.Serve(listener)
		require.NoError(t, err)
		done <- struct{}{}
	}()

	// client:
	clientAddr := mockColibriAddress(t, "1-ff00:0:112",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2346, Zone: ""})
	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquicgrpc"},
	}
	clientQuicConfig := &quic.Config{KeepAlive: true}

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	connDial := squic.ConnDialer{
		Conn:       newConnMock(t, clientAddr, thisNet),
		TLSConfig:  clientTlsConfig,
		QUICConfig: clientQuicConfig,
	}
	quicConn, err := connDial.Dial(ctx, serverAddr)
	require.NoError(t, err)
	dialer := func(context.Context, string) (net.Conn, error) {
		return quicConn, nil
	}
	conn, err := grpc.DialContext(ctx, serverAddr.String(), grpc.WithInsecure(),
		grpc.WithContextDialer(dialer))
	require.NoError(t, err)
	gRPCClient := colpb.NewColibriServiceClient(conn)
	res, err := gRPCClient.SegmentSetup(ctx, &colpb.SegmentSetupRequest{})
	require.NoError(t, err)
	require.IsType(t, path.Colibri{}, clientAddr.(*snet.UDPAddr).Path)
	require.Equal(t, clientAddr.(*snet.UDPAddr).Path.(path.Colibri).Raw, res.GetToken())
	require.True(t, testInterceptorCalled)

	gRPCServer.GracefulStop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out")
	}
}

// packet is a packet received by a mockNetwork.
type packet struct {
	sender net.Addr
	data   []byte
}

// mockNetwork is used to simulate a network, where packets are sent and read.
// The channels field organizes packets per receiver address (as string).
type mockNetwork struct {
	channels map[string]chan packet
	m        sync.Mutex
}

func newMockNetwork() *mockNetwork {
	return &mockNetwork{
		channels: make(map[string]chan packet),
	}
}

// ReadFrom returns the data from the first packet for receiver, and its sender.
func (n *mockNetwork) ReadFrom(receiver net.Addr) ([]byte, net.Addr) {
	key := receiver.String()
	n.ensureChannel(key)
	pac := <-n.channels[key]
	return pac.data, pac.sender
}

// WriteTo writes a packet from sender to receiver, with data.
func (n *mockNetwork) WriteTo(sender, receiver net.Addr, data []byte) {
	pac := packet{sender: sender, data: data}
	key := receiver.String()
	n.ensureChannel(key)
	n.channels[key] <- pac
}

func (n *mockNetwork) ensureChannel(key string) {
	n.m.Lock()
	defer n.m.Unlock()
	if _, found := n.channels[key]; !found {
		n.channels[key] = make(chan packet, 32)
	}
}

// mockScionAddress returns a SCION address with a SCION type path.
func mockScionAddress(t *testing.T, ia string, host *net.UDPAddr) net.Addr {
	t.Helper()
	return &snet.UDPAddr{
		IA:   xtest.MustParseIA(ia),
		Host: host,
		Path: path.SCION{
			Raw: xtest.MustParseHexString("0000208000000111000001000100022200000100003f0001" +
				"0000010203040506003f00030002010203040506003f00000002010203040506003f000100000" +
				"10203040506"),
		},
	}
}

// mockColibriAddress returns a SCION address with a Colibri path.
func mockColibriAddress(t *testing.T, ia string, host *net.UDPAddr) net.Addr {
	t.Helper()
	p := colibri.ColibriPath{
		PacketTimestamp: colibri.Timestamp{1},
		InfoField: &colibri.InfoField{
			C:           true,
			R:           false,
			S:           true,
			Ver:         1,
			CurrHF:      0,
			HFCount:     3,
			ResIdSuffix: xtest.MustParseHexString("beefcafe0000000000000000"),
			ExpTick:     1893452400, // valid until 1.1.2030
			BwCls:       7,
			Rlc:         7,
			OrigPayLen:  1208,
		},
		HopFields: []*colibri.HopField{
			{
				IngressId: 0,
				EgressId:  41,
				Mac:       []byte{140, 95, 102, 190}, // MAC is 4 bytes
			},
			{
				IngressId: 1,
				EgressId:  2,
				Mac:       []byte{0, 61, 66, 164},
			},
			{
				IngressId: 1,
				EgressId:  0,
				Mac:       xtest.MustParseHexString("00000000"),
			},
		},
	}
	buffLen := 8 + 24 + (len(p.HopFields) * 8) // timestamp + infofield + 3*hops
	buff := make([]byte, buffLen)
	err := p.SerializeTo(buff)
	require.NoError(t, err)

	return &snet.UDPAddr{
		IA:   xtest.MustParseIA(ia),
		Host: host,
		Path: path.Colibri{
			Raw: buff,
		},
	}
}

// connMock uses a mockNetwork to simulate a proper net.PacketConn.
type connMock struct {
	localAddr net.Addr
	net       *mockNetwork
}

var _ net.PacketConn = (*connMock)(nil)

func newConnMock(t *testing.T, localAddr net.Addr, network *mockNetwork) *connMock {
	t.Helper()
	require.NotNil(t, network)
	return &connMock{
		localAddr: localAddr,
		net:       network,
	}
}

func (c *connMock) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *connMock) Close() error {
	return nil
}

func (c *connMock) ReadFrom(p []byte) (int, net.Addr, error) {
	b, sender := c.net.ReadFrom(c.localAddr)
	n := copy(p, b)
	return n, sender, nil
}

func (c *connMock) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.net.WriteTo(c.localAddr, addr, p)
	return len(p), nil
}

func (c *connMock) SetDeadline(t time.Time) error {
	return nil
}

func (c *connMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *connMock) SetWriteDeadline(t time.Time) error {
	return nil
}

// createTestCertificate is based on https://github.com/lucas-clemente/quic-go/blob/
// e098ccd2b3bf560d3d8056dccc1a35b229a2a47a/example/echo/echo.go#L92
func createTestCertificate(t *testing.T) *tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return &tlsCert
}
