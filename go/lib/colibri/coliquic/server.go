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
package coliquic

import (
	"bytes"
	"context"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/svc"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
)

// GetColibriPath returns the (last) COLIBRI path used with this quic Session, or nil if none.
func GetColibriPath(session quic.Session) (*colibri.ColibriPath, error) {
	// TODO(juagargi) currently, the same session can receive packets from multitude of
	// COLIBRI paths (or non colibri), which should not be allowed. To enforce that the limits
	// of the reservation are respected, only one colibri path must be allowed thru the
	// life of the session. For now we assume no malicious parties.
	var colPath *colibri.ColibriPath
	netAddr := session.RemoteAddr()
	addr, _ := netAddr.(*snet.UDPAddr)
	if addr != nil {
		cp, err := reservation.PathFromDataplanePath(addr.Path)
		if err != nil {
			return nil, err
		}
		if cp.Type() == colibri.PathType {
			if colPath, _ = cp.(*colibri.ColibriPath); colPath == nil {
				// it's a colibri path, but not colibri.ColibriPath. Reconstruct from binary:
				buff := make([]byte, cp.Len())
				if err := cp.SerializeTo(buff); err != nil {
					return nil, err
				}
				colPath = &colibri.ColibriPath{}
				if err := colPath.DecodeFromBytes(buff); err != nil {
					return nil, err
				}
			}
		}
	}
	return colPath, nil
}

// NewConnListener adapts a quic.Listener to be a net.Listener.
func NewConnListener(listener quic.Listener) net.Listener {
	return squic.NewConnListener(listener)
}

type ServerStack struct {
	Daemon           daemon.Connector
	Router           snet.Router
	ClientPacketConn net.PacketConn
	Dialer           *libgrpc.QUICDialer
	Resolver         messenger.Resolver
	QUICListener     net.Listener
	TCPListener      net.Listener
	serverAddr       *snet.UDPAddr
	clientNet        *snet.SCIONNetwork
	serverNet        *snet.SCIONNetwork
}

func NewServerStack(ctx context.Context, serverAddr *snet.UDPAddr, daemonAddr string) (
	*ServerStack, error) {
	s := &ServerStack{}
	err := s.init(ctx, serverAddr, daemonAddr)
	return s, err
}

func (s *ServerStack) init(ctx context.Context, serverAddr *snet.UDPAddr, daemonAddr string) error {

	var err error
	if s.clientNet != nil {
		return serrors.New("already initialized")
	}

	s.serverAddr = serverAddr.Copy()
	s.Daemon, err = daemon.Service{
		Address: daemonAddr,
	}.Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}
	s.Router = &snet.BaseRouter{Querier: daemon.Querier{Connector: s.Daemon, IA: s.serverAddr.IA}}

	s.TCPListener, err = net.ListenTCP("tcp", &net.TCPAddr{
		IP:   serverAddr.Host.IP,
		Port: serverAddr.Host.Port,
		Zone: serverAddr.Host.Zone,
	})
	if err != nil {
		return err
	}

	client, server, err := s.initQUICSockets(ctx, daemonAddr)
	if err != nil {
		return err
	}
	s.ClientPacketConn = client

	// Generate throwaway self-signed TLS certificates. These DO NOT PROVIDE ANY SECURITY.
	ephemeralTLSConfig, err := infraenv.GenerateTLSConfig()
	if err != nil {
		return err
	}

	s.Resolver = &svc.Resolver{
		LocalIA: s.serverAddr.IA,
		// Reuse the network with SCMP error support.
		ConnFactory: s.clientNet.Dispatcher,
		LocalIP:     s.serverAddr.Host.IP,
	}

	quicClientDialer := &squic.ConnDialer{
		Conn:      client,
		TLSConfig: ephemeralTLSConfig,
	}
	s.Dialer = &libgrpc.QUICDialer{
		Dialer: quicClientDialer,
		Rewriter: &messenger.AddressRewriter{
			// Use the local Daemon to construct paths to the target AS.
			Router: s.Router,
			// We never resolve addresses in the local AS, so pass a nil here.
			SVCRouter: nil,
			Resolver: &svc.Resolver{
				LocalIA: s.serverAddr.IA,
				// Reuse the network with SCMP error support.
				ConnFactory: s.clientNet.Dispatcher,
				LocalIP:     s.serverAddr.Host.IP,
			},
			SVCResolutionFraction: 1.337,
		},
	}

	config := &quic.Config{
		KeepAlive: false, // TODO(juagargi) study if it'd be more performant to keep alive
	}
	s.QUICListener = NewListener(server, ephemeralTLSConfig, config)
	return nil
}

func (s *ServerStack) initQUICSockets(ctx context.Context, daemonAddr string) (
	net.PacketConn, net.PacketConn, error) {

	reconnectingDispatcher := reconnect.NewDispatcherService(reliable.NewDispatcher(""))

	revocationHandler := daemon.RevHandler{Connector: s.Daemon}

	s.clientNet = &snet.SCIONNetwork{
		LocalIA: s.serverAddr.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			// Enable transparent reconnections to the dispatcher
			Dispatcher: reconnectingDispatcher,
			// Forward revocations to Daemon
			SCMPHandler: snet.DefaultSCMPHandler{
				RevocationHandler: revocationHandler,
			},
		},
	}
	client, err := s.clientNet.Listen(
		ctx,
		"udp",
		&net.UDPAddr{IP: s.serverAddr.Host.IP},
		addr.SvcNone,
	)
	if err != nil {
		return nil, nil, serrors.WrapStr("initializing client QUIC connection", err)
	}

	// scionNetworkNoSCMP is the network for the QUIC server connection. Because SCMP errors
	// will cause the server's accepts to fail, we ignore SCMP.
	s.serverNet = &snet.SCIONNetwork{
		LocalIA: s.serverAddr.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			// Enable transparent reconnections to the dispatcher
			Dispatcher: reconnectingDispatcher,
			// Discard all SCMP, to avoid accept errors on the QUIC server.
			SCMPHandler: ignoreSCMP{},
		},
	}
	server, err := s.serverNet.Listen(
		context.TODO(),
		"udp",
		s.serverAddr.Host,
		addr.SvcNone,
	)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to initialize server QUIC connection", err)
	}
	return client, server, nil
}

func NewGrpcServer(opt ...grpc.ServerOption) *grpc.Server {
	h := &statsHandler{
		usage: make(map[string]uint64),
	}
	opts := append(opt, grpc.StatsHandler(h))
	return grpc.NewServer(opts...)
}

// UsageFromContext returns a bool saying if this peer was using colibri and
// an approximation of the bandwidth used in that case.
// TODO(juagargi) maybe use google.golang.org/protobuf/proto Size() instead?
func UsageFromContext(ctx context.Context) (bool, uint64, error) {
	// the context has a pointer to the statsHandler
	var handler *statsHandler
	if sh := ctx.Value(statsHandlerKey{}); sh != nil {
		handler = sh.(*statsHandler)
	}
	if handler == nil {
		return false, 0, serrors.New("could not retrieve handler from context",
			"raw_handler", ctx.Value(statsHandlerKey{}))
	}
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return false, 0, serrors.New("could not retrieve peer from context")
	}
	if raw := colibriRawPath(peer.Addr); raw != nil {
		usage, ok := handler.popUsage(raw)
		if !ok {
			return true, 0, serrors.New("could not retrieve this peer from stats handler",
				"peer", peer.Addr)
		}
		return true, usage, nil
	}
	return false, 0, nil
}

// statsHandlerKey is used as key inside context to store the pointer to its statsHandler.
type statsHandlerKey struct{}

// bandwidthKey used to store and retrieve the bandwidth used by a gRPC call.
type bandwidthKey struct{}

type statsHandler struct {
	usage map[string]uint64 // map of raw path to usage, incremented on each request
	m     sync.Mutex
}

func (h *statsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return ctx
}

func (h *statsHandler) HandleRPC(ctx context.Context, st stats.RPCStats) {
	logger := log.FromCtx(ctx)
	peer, ok := peer.FromContext((ctx))
	if !ok || peer.Addr.(*snet.UDPAddr) == nil {
		// not a SCION family address
		return
	}
	peerRaw := colibriRawPath(peer.Addr)
	prev := ctx.Value(bandwidthKey{})
	if prev == nil || prev.(*snet.UDPAddr) == nil {
		return
	}
	prevRaw := colibriRawPath(prev.(*snet.UDPAddr))
	if prevRaw == nil || !bytes.Equal(peerRaw, prevRaw) {
		logger.Info("error value from context not matching stats handler",
			"ctx_value", prev, "peer_addr", peer.Addr)
		return
	}
	handlerCtx := ctx.Value(statsHandlerKey{})
	if handlerCtx == nil || handlerCtx != h {
		logger.Info("error handler from context not matching stats handler",
			"ctx_handler", handlerCtx, "handler", h, "peer", peer.Addr)
		return
	}
	// estimate the size from the statistics
	var size int
	switch s := st.(type) {
	case *stats.Begin:
	case *stats.End:
	case *stats.OutHeader: // for some reason there's no length in it
	case *stats.InHeader:
		size = s.WireLength
	case *stats.InPayload:
		size = s.WireLength
	case *stats.InTrailer:
		size = s.WireLength
	case *stats.OutPayload:
		size = s.WireLength
	case *stats.OutTrailer:
		// this case is special: its wirelength is deprecated and never set
	default:
		logger.Info("error unknown stats type", "type", common.TypeOf(st))
		return
	}
	if size < 0 {
		logger.Info("error stats size is negative", "size", size, "peer", peer.Addr)
		return
	}
	h.addUsage(prevRaw, uint64(size))
}

func (h *statsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	if info.RemoteAddr.(*snet.UDPAddr) != nil {
		addr := info.RemoteAddr.(*snet.UDPAddr)
		raw := colibriRawPath(addr)
		if raw != nil {
			h.addUsage(raw, 0)
			// store a pointer to this stats handler in the context so that we can retrieve the
			// usage from the service calls themselves.
			ctx = context.WithValue(ctx, statsHandlerKey{}, h)
			// and for this context, add the address (should always match that of the peer)
			ctx = context.WithValue(ctx, bandwidthKey{}, addr)
		}
	}
	return ctx
}

func (h *statsHandler) HandleConn(ctx context.Context, st stats.ConnStats) {}

// popUsage returns the usage and the found indicator for a raw path in this statsHandler.
// if found, it will be removed.
// The call is intended to be used by one gRPC service call before its end.
func (h *statsHandler) popUsage(rawPath []byte) (uint64, bool) {
	key := string(rawPath)
	h.m.Lock()
	defer h.m.Unlock()
	usage, found := h.usage[key]
	if found {
		delete(h.usage, key)
	}
	return usage, found
}

func (h *statsHandler) addUsage(rawColibriPath []byte, usage uint64) {
	h.m.Lock()
	defer h.m.Unlock()
	h.usage[string(rawColibriPath)] += usage
}

// ignoreSCMP ignores all received SCMP packets.
//
// XXX(scrye): This is needed such that the QUIC server does not shut down when
// receiving a SCMP error. DO NOT REMOVE!
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	return nil
}

// colibriRawPath returns nil if a colibri path cannot be extracted from the address.
func colibriRawPath(addr net.Addr) []byte {
	if addr == nil || addr.(*snet.UDPAddr) == nil {
		return nil
	}
	p, err := reservation.PathFromDataplanePath(addr.(*snet.UDPAddr).Path)
	if err != nil || p == nil || p.Type() != colibri.PathType {
		return nil
	}
	buff, err := reservation.PathToRaw(p)
	if err != nil {
		return nil
	}
	return buff
}
