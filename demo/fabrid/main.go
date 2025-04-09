// Copyright 2024 ETH Zurich
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	libfabrid "github.com/scionproto/scion/pkg/experimental/fabrid"
	common2 "github.com/scionproto/scion/pkg/experimental/fabrid/common"
	fabridserver "github.com/scionproto/scion/pkg/experimental/fabrid/server"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/tracing"
	libint "github.com/scionproto/scion/tools/integration"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
)

const (
	ping = "ping"
	pong = "pong"
)

type Ping struct {
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

type Pong struct {
	Client  addr.IA `json:"client"`
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

var (
	remote                 snet.UDPAddr
	timeout                = &util.DurWrap{Duration: 10 * time.Second}
	scionPacketConnMetrics = metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter      = scionPacketConnMetrics.SCMPErrors
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Var(&remote, "remote", "")
	closeTracer, err := integration.InitTracer("fabrid-demo-" + integration.Mode)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()

	err = integration.Setup()
	if err != nil {
		log.Error("Parsing common flags failed", "err", err)
		return 1
	}
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	c := client{}
	return c.run()
}

type server struct {
	fabridServer *fabridserver.Server
}

func (s server) run() {
	fmt.Println("Starting server", "isd_as", integration.Local.IA)
	defer fmt.Println("Finished server", "isd_as", integration.Local.IA)

	sdConn := integration.SDConn()
	defer sdConn.Close()
	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          sdConn,
	}
	conn, err := sn.OpenRaw(context.Background(), integration.Local.Host)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", localAddr.Port)
		fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
	}
	fmt.Println("Listening", "local",
		fmt.Sprintf("%v:%d", integration.Local.Host.IP, localAddr.Port))
	s.fabridServer = fabridserver.NewFabridServer(&integration.Local, integration.SDConn())
	s.fabridServer.ValidationHandler = func(connection *fabridserver.ClientConnection,
		option *extension.IdentifierOption, b bool) error {
		fmt.Println("Validation handler", "connection", connection, "success", b)
		if !b {
			return serrors.New("Failed validation")
		}
		return nil
	}
	// Receive ping message
	for {
		if err := s.handlePingFabrid(conn); err != nil {
			log.Error("Error handling ping", "err", err)
		}
	}
}

func (s server) handlePingFabrid(conn snet.PacketConn) error {
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(conn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	var valResponse *slayers.EndToEndExtn

	// If the packet is from remote IA, validate the FABRID path
	if p.Source.IA != integration.Local.IA {
		if p.HbhExtension == nil {
			return serrors.New("Missing HBH extension")
		}

		// Check extensions for relevant options
		var identifierOption *extension.IdentifierOption
		var fabridOption *extension.FabridOption
		var controlOptions []*extension.FabridControlOption
		var err error

		for _, opt := range p.HbhExtension.Options {
			switch opt.OptType {
			case slayers.OptTypeIdentifier:
				decoded := scion.Decoded{}
				err = decoded.DecodeFromBytes(p.Path.(snet.RawPath).Raw)
				if err != nil {
					return err
				}
				baseTimestamp := decoded.InfoFields[0].Timestamp
				identifierOption, err = extension.ParseIdentifierOption(opt, baseTimestamp)
				if err != nil {
					return err
				}
			case slayers.OptTypeFabrid:
				fabridOption, err = extension.ParseFabridOptionFullExtension(opt,
					(opt.OptDataLen-4)/4)
				if err != nil {
					return err
				}
			}
		}
		if p.E2eExtension != nil {

			for _, opt := range p.E2eExtension.Options {
				switch opt.OptType {
				case slayers.OptTypeFabridControl:
					controlOption, err := extension.ParseFabridControlOption(opt)
					if err != nil {
						return err
					}
					controlOptions = append(controlOptions, controlOption)
				}
			}
		}

		if identifierOption == nil {
			return serrors.New("Missing identifier option")
		}

		if fabridOption == nil {
			return serrors.New("Missing FABRID option")
		}
		valResponse, err = s.fabridServer.HandleFabridPacket(p.Source, fabridOption,
			identifierOption, controlOptions)
		if err != nil {
			return err
		}
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Ping
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.New("invalid payload contents",
			"source", p.Source,
			"destination", p.Destination,
			"data", string(udp.Payload),
		)
	}
	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.WrapStr("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		))
	}
	fmt.Printf("Ping received from %s, sending pong.", p.Source)
	raw, err := json.Marshal(Pong{
		Client:  p.Source.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.WrapStr("packing pong", err))
	}

	p.Destination, p.Source = p.Source, p.Destination
	p.Payload = snet.UDPPayload{
		DstPort: udp.SrcPort,
		SrcPort: udp.DstPort,
		Payload: raw,
	}

	// Remove header extension for reverse path
	p.HbhExtension = nil
	p.E2eExtension = valResponse

	// reverse path
	rpath, ok := p.Path.(snet.RawPath)
	if !ok {
		return serrors.New("unexpected path", "type", common.TypeOf(p.Path))
	}
	replypather := snet.DefaultReplyPather{}
	replyPath, err := replypather.ReplyPath(rpath)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	p.Path = replyPath
	// Send pong
	if err := conn.WriteTo(&p, &ov); err != nil {
		return withTag(serrors.WrapStr("sending reply", err))
	}
	fmt.Println("Sent pong to", "client", p.Destination)
	return nil
}

type client struct {
	network *snet.SCIONNetwork
	rawConn snet.PacketConn
	sdConn  daemon.Connector

	errorPaths map[snet.PathFingerprint]struct{}
}

func (c *client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	fmt.Println("Starting", "pair", pair)
	defer fmt.Println("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	c.sdConn = integration.SDConn()
	defer c.sdConn.Close()
	c.network = &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: c.sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          c.sdConn,
	}
	fmt.Println("Send", "local",
		fmt.Sprintf("%v,[%v] -> %v,[%v]",
			integration.Local.IA, integration.Local.Host,
			remote.IA, remote.Host))
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

// attemptRequest sends one ping packet and expect a pong.
// Returns true (which means "stop") *if both worked*.
func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "attempt")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}
	span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	doFabridPing := func() bool {
		// Send ping
		close, err := c.fabridPing(ctx, n)
		if err != nil {
			logger.Error("Could not send packet", "err", withTag(err))
			return false
		}
		defer close()
		// Receive FABRID pong
		if err := c.fabridPong(ctx); err != nil {
			logger.Error("Error receiving pong", "err", withTag(err))
			if path != nil {
				c.errorPaths[snet.Fingerprint(path)] = struct{}{}
			}
			return false
		}
		return true
	}

	for i := 0; i < 10; i++ {
		if !doFabridPing() {
			return false
		}
	}
	return true
}

func (c *client) fabridPing(ctx context.Context, n int) (func(), error) {
	pping := Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	}
	rawPing, err := json.Marshal(pping)
	if err != nil {
		return nil, serrors.WrapStr("packing ping", err)
	}
	log.FromCtx(ctx).Info("Dialing", "remote", remote)
	c.rawConn, err = c.network.OpenRaw(ctx, integration.Local.Host)
	if err != nil {
		return nil, serrors.WrapStr("dialing conn", err)
	}
	if err := c.rawConn.SetWriteDeadline(getDeadline(ctx)); err != nil {
		return nil, serrors.WrapStr("setting write deadline", err)
	}
	fmt.Println("sending ping", "attempt", n, "remote", remote, "local", c.rawConn.LocalAddr())
	localAddr := c.rawConn.LocalAddr().(*net.UDPAddr)
	hostIP, _ := netip.AddrFromSlice(remote.Host.IP)
	dst := snet.SCIONAddress{IA: remote.IA, Host: addr.HostIP(hostIP)}
	localHostIP, _ := netip.AddrFromSlice(integration.Local.Host.IP)
	pkt := &snet.Packet{
		Bytes: make([]byte, common.SupportedMTU),
		PacketInfo: snet.PacketInfo{
			Destination: dst,
			Source: snet.SCIONAddress{
				IA:   integration.Local.IA,
				Host: addr.HostIP(localHostIP),
			},
			Path: remote.Path,
			Payload: snet.UDPPayload{
				SrcPort: uint16(localAddr.Port),
				DstPort: uint16(remote.Host.Port),
				Payload: rawPing,
			},
		},
	}
	fmt.Println("sending packet")
	if err := c.rawConn.WriteTo(pkt, remote.NextHop); err != nil {
		return nil, err
	}
	closer := func() {
		if err := c.rawConn.Close(); err != nil {
			log.Error("Unable to close connection", "err", err)
		}
	}
	return closer, nil
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	span, ctx := tracing.StartSpanFromCtx(ctx, "attempt.get_remote")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemon.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, withTag(serrors.WrapStr("requesting paths", err))
	}
	// If all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	// Select first path that didn't error before.
	var path snet.Path
	for _, p := range paths {
		if _, ok := c.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		path = p
		break
	}
	if path == nil {
		return nil, withTag(serrors.New("no path found",
			"candidates", len(paths),
			"errors", len(c.errorPaths),
		))
	}
	// If the fabrid flag is set, try to create FABRID dataplane path.
	if len(path.Metadata().FabridInfo) > 0 {
		// Check if fabrid info is available, otherwise the source
		// AS does not support fabrid

		scionPath, ok := path.Dataplane().(snetpath.SCION)
		if !ok {
			return nil, serrors.New("provided path must be of type scion")
		}
		fabridConfig := &snetpath.FabridConfig{
			LocalIA:         integration.Local.IA,
			LocalAddr:       integration.Local.Host.IP.String(),
			DestinationIA:   remote.IA,
			DestinationAddr: remote.Host.IP.String(),
			ValidationRatio: 128,
		}
		fabridConfig.ValidationHandler = func(ps *common2.PathState,
			option *extension.FabridControlOption, b bool) error {
			fmt.Println("Validation handler", "pathState", ps, "success", b)
			if !b {
				return serrors.New("Failed validation")
			}
			return nil
		}
		hops := path.Metadata().Hops()
		fmt.Println("Fabrid path", "path", path, "hops", hops)
		// Use ZERO policy for all hops with fabrid, to just do path validation
		policies := make([]*libfabrid.PolicyID, len(hops))
		zeroPol := libfabrid.PolicyID(0)
		for i, hop := range hops {
			if hop.FabridEnabled {
				policies[i] = &zeroPol
			}
		}
		fabridPath, err := snetpath.NewFABRIDDataplanePath(scionPath, hops,
			policies, fabridConfig, c.sdConn.FabridKeys)
		if err != nil {
			return nil, serrors.New("Error creating FABRID path", "err", err)
		}
		remote.Path = fabridPath

	} else {
		fmt.Printf("FABRID flag was set for client in non-FABRID AS. Proceeding without FABRID.")
		remote.Path = path.Dataplane()
	}
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) fabridPong(ctx context.Context) error {

	if err := c.rawConn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(c.rawConn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}
	if p.Source.IA != integration.Local.IA {
		// Check extensions for relevant options
		var controlOptions []*extension.FabridControlOption

		if p.E2eExtension != nil {

			for _, opt := range p.E2eExtension.Options {
				switch opt.OptType {
				case slayers.OptTypeFabridControl:
					controlOption, err := extension.ParseFabridControlOption(opt)
					if err != nil {
						return err
					}
					controlOptions = append(controlOptions, controlOption)
				}
			}
		}
		switch s := remote.Path.(type) {
		case *snetpath.FABRID:
			for _, option := range controlOptions {
				err := s.HandleFabridControlOption(option, nil)
				if err != nil {
					return err
				}
			}

		default:
			return serrors.New("unsupported path type")
		}
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Pong
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.WrapStr("unpacking pong", err, "data", string(udp.Payload))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
	}
	fmt.Println("Received pong", "server", ov)
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	dl, ok := ctx.Deadline()
	if !ok {
		integration.LogFatal("No deadline in context")
	}
	return dl
}

func readFromFabrid(conn snet.PacketConn, pkt *snet.Packet, ov *net.UDPAddr) error {
	err := conn.ReadFrom(pkt, ov)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return err
	}
	return serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}
