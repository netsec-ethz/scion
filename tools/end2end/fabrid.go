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
	"fmt"
	"net"
	"net/netip"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/tracing"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
)

func (c *client) fabridPing(ctx context.Context, n int, path snet.Path) (func(), error) {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
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
	log.Info("sending ping", "attempt", n, "remote", remote, "local", c.rawConn.LocalAddr())
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
	log.Info("sending packet", "packet", pkt)
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
	log.Info(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
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
	log.Info("Sent pong to", "client", p.Destination)
	return nil
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
					log.Debug("Parsed control option", "option", controlOption)
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
	log.Info("Received pong", "server", ov)
	return nil
}
