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

package server

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid/common"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
)

type ClientConnection struct {
	Source              snet.SCIONAddress
	ValidationRatio     uint8
	Stats               common.Statistics
	fabridControlBuffer []byte
	tmpBuffer           []byte
	pathKey             drkey.Key
}

type Server struct {
	Local              snet.UDPAddr
	sdConn             daemon.Connector
	Connections        map[string]*ClientConnection
	ASKeyCache         map[addr.IA]drkey.HostASKey
	MaxValidationRatio uint8
	ValidationHandler  func(*ClientConnection, *extension.IdentifierOption, bool) error
}

// NewFabridServer initializes a state registry for FABRID connections from remote endhosts
// to this endhost (hence called server)
func NewFabridServer(local *snet.UDPAddr, sdConn daemon.Connector) *Server {
	server := &Server{
		Local:       *local,
		sdConn:      sdConn,
		Connections: make(map[string]*ClientConnection),
		ASKeyCache:  make(map[addr.IA]drkey.HostASKey),
		ValidationHandler: func(_ *ClientConnection, _ *extension.IdentifierOption, _ bool) error {
			return nil
		},
		MaxValidationRatio: 255,
	}
	return server
}

func (s *Server) FetchHostHostKey(dstHost snet.SCIONAddress,
	validity time.Time) (drkey.Key, error) {
	meta := drkey.HostHostMeta{
		Validity: validity,
		SrcIA:    s.Local.IA,
		SrcHost:  s.Local.Host.IP.String(),
		DstIA:    dstHost.IA,
		DstHost:  dstHost.Host.IP().String(),
		ProtoId:  drkey.FABRID,
	}
	hostHostKey, err := s.sdConn.DRKeyGetHostHostKey(context.Background(), meta)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("getting host key", err)
	}
	return hostHostKey.Key, nil
}

// HandleFabridPacket takes care of the FABRID validation state per remote, extracts the
// FABRID control options, processes them and adds the result to the validation response
func (s *Server) HandleFabridPacket(remote snet.SCIONAddress, fabridOption *extension.FabridOption,
	identifierOption *extension.IdentifierOption,
	controlOptions []*extension.FabridControlOption) (*slayers.EndToEndExtn, error) {
	client, found := s.Connections[remote.String()]
	if !found {
		pathKey, err := s.FetchHostHostKey(remote, identifierOption.Timestamp)
		if err != nil {
			return nil, err
		}
		client = &ClientConnection{
			Source:              remote,
			ValidationRatio:     255,
			Stats:               common.Statistics{},
			fabridControlBuffer: make([]byte, 28*3),
			tmpBuffer:           make([]byte, 192),
			pathKey:             pathKey,
		}
		s.Connections[remote.String()] = client
		log.Info("Opened new connection", "remote", remote.String())
	}

	client.Stats.TotalPackets++
	validationNumber, validationReply, err := crypto.VerifyPathValidator(fabridOption,
		client.tmpBuffer, client.pathKey[:])
	if err != nil {
		return nil, err
	}
	err = s.ValidationHandler(client, identifierOption, err == nil)
	if err != nil {
		client.Stats.InvalidPackets++
		return nil, err
	}

	var replyOpts []*extension.FabridControlOption
	// here we iterate over all FABRID control options. This can be a validation config to
	// set the requested validation ratio or a statistic request which asks for a statistics
	// response containing the number of total packets and the number of invalid packets
	for _, controlOption := range controlOptions {
		err = crypto.VerifyFabridControlValidator(controlOption, identifierOption,
			client.pathKey[:])
		if err != nil {
			return nil, err
		}
		controlReplyOpt := &extension.FabridControlOption{}

		switch controlOption.Type {
		case extension.ValidationConfig:
			requestedRatio, err := controlOption.ValidationRatio()
			if err != nil {
				return nil, err
			}
			if requestedRatio > s.MaxValidationRatio {
				log.Debug("FABRID control: requested ratio too large", "requested", requestedRatio,
					"max", s.MaxValidationRatio)
				requestedRatio = s.MaxValidationRatio
			}
			log.Debug("FABRID control: updated validation ratio", "new", requestedRatio,
				"old", client.ValidationRatio)
			client.ValidationRatio = requestedRatio

			// Prepare ACK
			controlReplyOpt.Type = extension.ValidationConfigAck
			controlReplyOpt.Data = make([]byte, 9)
			err = controlReplyOpt.SetValidationRatio(client.ValidationRatio)
			if err != nil {
				return nil, err
			}
		case extension.StatisticsRequest:
			log.Debug("FABRID control: statistics request")
			// Prepare statistics reply
			controlReplyOpt.Type = extension.StatisticsResponse
			controlReplyOpt.Data = make([]byte, 24)
			err := controlReplyOpt.SetStatistics(client.Stats.TotalPackets,
				client.Stats.InvalidPackets)
			if err != nil {
				return nil, err
			}
		}
		ts, _ := controlOption.Timestamp()
		err = controlReplyOpt.SetTimestamp(ts)
		if err != nil {
			return nil, err
		}
		packetID, _ := controlOption.PacketID()
		err = controlReplyOpt.SetPacketID(packetID)
		if err != nil {
			return nil, err
		}
		replyOpts = append(replyOpts, controlReplyOpt)
	}
	// if the computed validation number is smaller than the configured validation ratio,
	// a validation reply e2e option will be added to the validation response.
	if validationNumber < client.ValidationRatio {
		log.Debug("Send validation response", "packetID", identifierOption.PacketID,
			"timestamp", identifierOption.GetRelativeTimestamp())
		validationReplyOpt := extension.NewFabridControlOption(extension.ValidationResponse)
		err = validationReplyOpt.SetTimestamp(identifierOption.GetRelativeTimestamp())
		if err != nil {
			return nil, err
		}
		err = validationReplyOpt.SetPacketID(identifierOption.PacketID)
		if err != nil {
			return nil, err
		}
		replyOpts = append(replyOpts, validationReplyOpt)
		err = validationReplyOpt.SetPathValidatorReply(validationReply)
		if err != nil {
			return nil, err
		}
	}

	if len(replyOpts) > 0 {
		e2eExt := &slayers.EndToEndExtn{}
		for i, replyOpt := range replyOpts {
			err = crypto.InitFabridControlValidator(replyOpt, identifierOption, client.pathKey[:])
			if err != nil {
				return nil, err
			}
			buffer := client.fabridControlBuffer[i*28 : (i+1)*28]
			err = replyOpt.SerializeTo(buffer)
			if err != nil {
				return nil, err
			}
			fabridReplyOptionLength := extension.BaseFabridControlLen +
				extension.FabridControlOptionDataLen(replyOpt.Type)
			e2eExt.Options = append(e2eExt.Options,
				&slayers.EndToEndOption{
					OptType:      slayers.OptTypeFabridControl,
					OptData:      buffer,
					OptDataLen:   uint8(fabridReplyOptionLength),
					ActualLength: fabridReplyOptionLength,
				})
		}
		return e2eExt, nil
	}
	return nil, nil
}
