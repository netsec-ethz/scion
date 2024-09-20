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

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/tracing"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
)

func (s server) handlePingFabrid(conn snet.PacketConn) error {
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(conn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	// If the packet is from remote IA, validate the FABRID path
	if p.Source.IA != integration.Local.IA {
		if p.HbhExtension == nil {
			return serrors.New("Missing HBH extension")
		}

		// Check extensions for relevant options
		var identifierOption *extension.IdentifierOption
		var fabridOption *extension.FabridOption
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

		if identifierOption == nil {
			return serrors.New("Missing identifier option")
		}

		if fabridOption == nil {
			return serrors.New("Missing FABRID option")
		}

		meta := drkey.HostHostMeta{
			Validity: identifierOption.Timestamp,
			SrcIA:    integration.Local.IA,
			SrcHost:  integration.Local.Host.IP.String(),
			DstIA:    p.Source.IA,
			DstHost:  p.Source.Host.IP().String(),
			ProtoId:  drkey.FABRID,
		}
		hostHostKey, err := integration.SDConn().DRKeyGetHostHostKey(context.Background(), meta)
		if err != nil {
			return serrors.WrapStr("getting host key", err)
		}

		tmpBuffer := make([]byte, (len(fabridOption.HopfieldMetadata)*3+15)&^15+16)
		_, err = crypto.VerifyPathValidator(fabridOption, tmpBuffer, hostHostKey.Key[:])
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
	p.E2eExtension = nil

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
