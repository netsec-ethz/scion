// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package infraenv contains convenience function common to SCION infra
// services.
package infraenv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"inet.af/netaddr"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/svc"
)

// QUIC contains the QUIC configuration for control-plane speakers.
type QUIC struct {
	// Address is the UDP address to start the QUIC server on.
	Address string
}

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public              *net.UDPAddr
	TrustAddr           *net.UDPAddr
	DRKeyAddr           *net.UDPAddr
	ChainRenewalAddr    *net.UDPAddr
	SegLookupAddr       *net.UDPAddr
	SegRegistrationAddr *net.UDPAddr
	// ReconnectToDispatcher sets up sockets that automatically reconnect if
	// the dispatcher closes the connection (e.g., if the dispatcher goes
	// down).
	ReconnectToDispatcher bool
	// QUIC contains configuration details for QUIC servers. If the listening
	// address is the empty string, then no QUIC socket is opened.
	QUIC QUIC
	// SVCRouter is used to discover the underlay addresses of intra-AS SVC
	// servers.
	SVCRouter messenger.LocalSVCRouter
	// SCMPHandler is the SCMP handler to use. This handler is only applied to
	// client connections. The connection the server listens on will always
	// ignore SCMP messages. Otherwise, the server will shutdown when receiving
	// an SCMP error message.
	SCMPHandler snet.SCMPHandler
}

// QUICStack contains everything to run a QUIC based RPC stack.
type QUICStack struct {
	Listener       *squic.ConnListener
	Dialer         *squic.ConnDialer
	TLSListener    *squic.ConnListener
	TLSDialer      *squic.ConnDialer
	TrustListener  *squic.ConnListener
	DRKeyListener  *squic.ConnListener
	DRKeyDialer    *squic.ConnDialer
	CSListeners    []*squic.ConnListener
	RedirectCloser func()
}

func (q *QUICStack) FindListenerIndex(a *net.UDPAddr) (int, error) {
	ipPort, ok := netaddr.FromStdAddr(a.IP, a.Port, a.Zone)
	if !ok {
		return -1, serrors.New("cannot convert addr", "addr", a.String())
	}
	for i, lis := range q.CSListeners {
		lisAddr, err := netaddr.ParseIPPort(lis.Addr().String())
		if err != nil {
			return -1, serrors.New("cannot convert listener addr",
				"addr", lis.Addr().String())
		}
		if lisAddr == ipPort {
			return i, nil
		}
	}
	return -1, serrors.New("address not found in listeners", "addr", a.String())
}

func (nc *NetworkConfig) TCPStack() (net.Listener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{
		IP:   nc.Public.IP,
		Port: nc.Public.Port,
		Zone: nc.Public.Zone,
	})
}

func (nc *NetworkConfig) uniqueQUICAddresses() []*net.UDPAddr {
	var ipPort netaddr.IPPort
	var ok bool
	set := make(map[netaddr.IPPort]struct{})
	ipPort, ok = netaddr.FromStdAddr(nc.TrustAddr.IP, nc.TrustAddr.Port, nc.TrustAddr.Zone)
	if ok {
		set[ipPort] = struct{}{}
	}
	ipPort, ok = netaddr.FromStdAddr(nc.ChainRenewalAddr.IP, nc.ChainRenewalAddr.Port, nc.ChainRenewalAddr.Zone)
	if ok {
		set[ipPort] = struct{}{}
	}
	ipPort, ok = netaddr.FromStdAddr(nc.SegLookupAddr.IP, nc.SegLookupAddr.Port, nc.SegLookupAddr.Zone)
	if ok {
		set[ipPort] = struct{}{}
	}
	ipPort, ok = netaddr.FromStdAddr(nc.SegRegistrationAddr.IP, nc.SegRegistrationAddr.Port, nc.SegRegistrationAddr.Zone)
	if ok {
		set[ipPort] = struct{}{}
	}
	addrSlice := []*net.UDPAddr{}
	for ipPort := range set {
		addrSlice = append(addrSlice, ipPort.UDPAddr())
	}
	return addrSlice
}

func (nc *NetworkConfig) initCSListeners() ([]*squic.ConnListener, error) {
	csAddresses := nc.uniqueQUICAddresses()
	tlsConfig, err := GenerateTLSConfig()
	if err != nil {
		return nil, err
	}
	listeners := make([]*squic.ConnListener, len(csAddresses))
	for i, a := range csAddresses {
		server, err := nc.initQUICServerSocket(a)
		if err != nil {
			return nil, serrors.WrapStr("initing CS server socket", err, "address", a.String())
		}
		lis, err := quic.Listen(server, tlsConfig, nil)
		if err != nil {
			return nil, err
		}
		listeners[i] = squic.NewConnListener(lis)
	}
	return listeners, nil
}

func (nc *NetworkConfig) QUICStack() (*QUICStack, error) {
	if nc.QUIC.Address == "" {
		nc.QUIC.Address = net.JoinHostPort(nc.Public.IP.String(), "0")
	}
	client, server, err := nc.initQUICSockets(false)
	if err != nil {
		return nil, err
	}
	log.Info("QUIC server conn initialized", "local_addr", server.LocalAddr())
	log.Info("QUIC client conn initialized", "local_addr", client.LocalAddr())

	tlsConfig, err := GenerateTLSConfig()
	if err != nil {
		return nil, err
	}
	listener, err := quic.Listen(server, tlsConfig, nil)
	if err != nil {
		return nil, serrors.WrapStr("listening QUIC/SCION", err)
	}

	//TLS/QUIC part
	// Calling initQUICSockets again will fail if nc.QUIC.Address has a port other than 0.
	// As a workaround, forcefully set the port to 0 via a parameter.

	tlsQuicConfig, err := GenerateTLSConfig()
	if err != nil {
		return nil, err
	}

	// tlsClient, tlsServer, err := nc.initQUICSockets(true)
	// if err != nil {
	// 	return nil, err
	// }
	// log.Info("TLS/QUIC server conn initialized", "local_addr", tlsServer.LocalAddr())
	// log.Info("TLS/QUIC client conn initialized", "local_addr", tlsClient.LocalAddr())

	// tlsListener, err := quic.Listen(tlsServer, tlsQuicConfig, nil)
	// if err != nil {
	// 	return nil, serrors.WrapStr("listening TLS/QUIC/SCION", err)
	// }

	cancel, err := nc.initSvcRedirect(server.LocalAddr().String())
	if err != nil {
		return nil, serrors.WrapStr("starting service redirection", err)
	}

	drkeyClient, drkeyServer, err := nc.initQUICSocketDRKey()
	if err != nil {
		return nil, err
	}
	log.Info("DRKey server conn initialized", "local_addr", drkeyServer.LocalAddr())
	drkeyListener, err := quic.Listen(drkeyServer, tlsQuicConfig, nil)
	if err != nil {
		return nil, serrors.WrapStr("listening QUIC/SCION for DRKey socket", err)
	}

	csListeners, err := nc.initCSListeners()
	if err != nil {
		return nil, serrors.WrapStr("listening QUIC/SCION for CS servers sockets", err)
	}

	return &QUICStack{
		Listener: squic.NewConnListener(listener),
		Dialer: &squic.ConnDialer{
			Conn:      client,
			TLSConfig: tlsConfig,
		},
		// TLSListener: squic.NewConnListener(tlsListener),
		// TLSDialer: &squic.ConnDialer{
		// 	Conn:      tlsClient,
		// 	TLSConfig: tlsQuicConfig,
		// },
		DRKeyListener: squic.NewConnListener(drkeyListener),
		DRKeyDialer: &squic.ConnDialer{
			Conn:      drkeyClient,
			TLSConfig: tlsQuicConfig,
		},
		CSListeners:    csListeners,
		RedirectCloser: cancel,
	}, nil
}

// GenerateTLSConfig generates a self-signed certificate.
func GenerateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, serrors.WrapStr("creating random serial number", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "scion_def_srv",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"SCION"},
	}, nil
}

// AddressRewriter initializes path and svc resolvers for infra servers.
//
// The connection factory is used to open sockets for SVC resolution requests.
// If the connection factory is nil, the default connection factory is used.
func (nc *NetworkConfig) AddressRewriter(
	connFactory snet.PacketDispatcherService) *messenger.AddressRewriter {

	if connFactory == nil {
		connFactory = &snet.DefaultPacketDispatcherService{
			Dispatcher:  reliable.NewDispatcher(""),
			SCMPHandler: nc.SCMPHandler,
		}
	}
	return &messenger.AddressRewriter{
		Router:    &snet.BaseRouter{Querier: snet.IntraASPathQuerier{IA: nc.IA}},
		SVCRouter: nc.SVCRouter,
		Resolver: &svc.Resolver{
			LocalIA:     nc.IA,
			ConnFactory: connFactory,
			LocalIP:     nc.Public.IP,
		},
		SVCResolutionFraction: 1.337,
	}
}

// initSvcRedirect creates the main control-plane UDP socket. SVC anycasts will be
// delivered to this socket, which replies to SVC resolution requests. The
// address will be included as the QUIC address in SVC resolution replies.
func (nc *NetworkConfig) initSvcRedirect(quicAddress string) (func(), error) {
	reply := &svc.Reply{
		Transports: map[svc.Transport]string{
			svc.QUIC: quicAddress,
		},
	}

	svcResolutionReply, err := reply.Marshal()
	if err != nil {
		return nil, serrors.WrapStr("building SVC resolution reply", err)
	}

	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	packetDispatcher := svc.NewResolverPacketDispatcher(
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  dispatcherService,
			SCMPHandler: nc.SCMPHandler,
		},
		&svc.BaseHandler{
			Message: svcResolutionReply,
		},
	)
	network := &snet.SCIONNetwork{
		LocalIA:    nc.IA,
		Dispatcher: packetDispatcher,
	}
	conn, err := network.Listen(context.Background(), "udp", nc.Public, addr.SvcWildcard)
	if err != nil {
		return nil, serrors.WrapStr("listening on SCION", err, "addr", nc.Public)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer log.HandlePanic()
		buf := make([]byte, 1500)
		done := ctx.Done()
		for {
			select {
			case <-done:
				return
			default:
				conn.Read(buf)
			}
		}
	}()
	return cancel, nil
}

func (nc *NetworkConfig) initQUICSockets(ignorePort bool) (net.PacketConn, net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	serverNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
			// XXX(roosd): This is essential, the server must not read SCMP
			// errors. Otherwise, the accept loop will always return that error
			// on every subsequent call to accept.
			SCMPHandler: ignoreSCMP{},
		},
	}
	serverAddr, err := net.ResolveUDPAddr("udp", nc.QUIC.Address)
	if err != nil {
		return nil, nil, serrors.WrapStr("parsing server QUIC address", err)
	}
	if ignorePort {
		serverAddr.Port = 0
	}
	server, err := serverNet.Listen(context.Background(), "udp", serverAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating server connection", err)
	}

	clientNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher:  dispatcherService,
			SCMPHandler: nc.SCMPHandler,
		},
	}
	// Let the dispatcher decide on the port for the client connection.
	clientAddr := &net.UDPAddr{
		IP:   serverAddr.IP,
		Zone: serverAddr.Zone,
	}
	client, err := clientNet.Listen(context.Background(), "udp", clientAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating client connection", err)
	}
	return client, server, nil
}

func (nc *NetworkConfig) initQUICSocketTrust() (net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	serverNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
			// XXX(roosd): This is essential, the server must not read SCMP
			// errors. Otherwise, the accept loop will always return that error
			// on every subsequent call to accept.
			SCMPHandler: ignoreSCMP{},
		},
	}
	server, err := serverNet.Listen(context.Background(), "udp", nc.TrustAddr, addr.SvcNone)
	if err != nil {
		return nil, serrors.WrapStr("creating server connection", err)
	}
	return server, nil
}

func (nc *NetworkConfig) initQUICServerSocket(lisAddr *net.UDPAddr) (net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	serverNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
			// XXX(roosd): This is essential, the server must not read SCMP
			// errors. Otherwise, the accept loop will always return that error
			// on every subsequent call to accept.
			SCMPHandler: ignoreSCMP{},
		},
	}
	log.Debug("initServerSocket", "address", lisAddr.String())
	server, err := serverNet.Listen(context.Background(), "udp", lisAddr, addr.SvcNone)
	if err != nil {
		return nil, serrors.WrapStr("creating server connection", err)
	}
	return server, nil
}

func (nc *NetworkConfig) initQUICSocketDRKey() (net.PacketConn, net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	serverNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
			// XXX(roosd): This is essential, the server must not read SCMP
			// errors. Otherwise, the accept loop will always return that error
			// on every subsequent call to accept.
			SCMPHandler: ignoreSCMP{},
		},
	}
	server, err := serverNet.Listen(context.Background(), "udp", nc.DRKeyAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating server connection", err)
	}

	clientNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher:  dispatcherService,
			SCMPHandler: nc.SCMPHandler,
		},
	}
	// Let the dispatcher decide on the port for the client connection.
	clientAddr := &net.UDPAddr{
		IP:   nc.DRKeyAddr.IP,
		Zone: nc.DRKeyAddr.Zone,
	}
	client, err := clientNet.Listen(context.Background(), "udp", clientAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating client connection", err)
	}
	return client, server, nil
}

// NewRouter constructs a path router for paths starting from localIA.
func NewRouter(localIA addr.IA, sd env.Daemon) (snet.Router, error) {
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(sd.InitialConnectPeriod.Duration)
	ctx, cancelF := context.WithTimeout(context.Background(), sd.InitialConnectPeriod.Duration)
	defer cancelF()
	defer ticker.Stop()
	defer timer.Stop()
	// XXX(roosd): Initial retrying is implemented here temporarily.
	// In https://github.com/scionproto/scion/issues/1974 this will be
	// done transparently and pushed to snet.NewNetwork.
	var router snet.Router
	for {
		daemonConn, err := daemon.NewService(sd.Address).Connect(ctx)
		if err == nil {
			router = &snet.BaseRouter{
				Querier: daemon.Querier{
					Connector: daemonConn,
					IA:        localIA,
				},
			}
			break
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return nil, serrors.WrapStr("Timed out during initial daemon connect", err)
		}
	}
	return router, nil
}

func InitInfraEnvironment(topologyPath string) {
	InitInfraEnvironmentFunc(topologyPath, nil)
}

// InitInfraEnvironmentFunc sets up the environment by first calling
// env.RealoadTopology and then the provided function.
func InitInfraEnvironmentFunc(topologyPath string, f func()) {
	env.SetupEnv(
		func() {
			env.ReloadTopology(topologyPath)
			if f != nil {
				f()
			}
		},
	)
}

// ignoreSCMP ignores all received SCMP packets.
//
// XXX(roosd): This is needed such that the QUIC server does not shut down when
// receiving a SCMP error. DO NOT REMOVE!
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}
