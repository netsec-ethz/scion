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

package path

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/experimental/fabrid/common"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

type FabridConfig struct {
	LocalIA           addr.IA
	LocalAddr         string
	DestinationIA     addr.IA
	DestinationAddr   string
	ValidationHandler func(*common.PathState, *extension.FabridControlOption, bool) error
	ValidationRatio   uint8
}

type FABRID struct {
	Raw              []byte
	keys             map[addr.IA]*drkey.FabridKey
	pathKey          *drkey.FabridKey
	getFabridKeys    func(context.Context, drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error)
	conf             *FabridConfig
	counter          uint32
	baseTimestamp    uint32
	tmpBuffer        []byte
	identifierBuffer []byte
	fabridBuffer     []byte
	e2eBuffer        []byte
	policyIDs        []*fabrid.PolicyID
	numHops          int
	hops             []snet.HopInterface
	pathState        *common.PathState
}

// Initializes a FABRID Dataplane path. The probability of requesting a source validation
// action is roughly 'validationRatio'/256.
func NewFABRIDDataplanePath(p SCION, hops []snet.HopInterface, policyIDs []*fabrid.PolicyID,
	conf *FabridConfig, getFabridKeys func(context.Context, drkey.FabridKeysMeta) (
		drkey.FabridKeysResponse, error)) (*FABRID, error) {

	numHops := len(hops)
	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(p.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	keys := make(map[addr.IA]*drkey.FabridKey)
	if len(policyIDs) == 0 { // If no policies are provided, use empty policy for all hops
		policyIDs = make([]*fabrid.PolicyID, numHops)
	} else if len(policyIDs) != numHops {
		return nil, serrors.New("Amount of policy ids does not match the amount of hops in " +
			"the path.")
	}
	var pathKey *drkey.FabridKey
	if hops[numHops-1].FabridEnabled {
		pathKey = &drkey.FabridKey{}
	}
	f := &FABRID{
		hops:             hops,
		numHops:          numHops,
		conf:             conf,
		keys:             keys,
		pathKey:          pathKey,
		tmpBuffer:        make([]byte, 64),
		identifierBuffer: make([]byte, 8),
		fabridBuffer:     make([]byte, 8+4*numHops),
		e2eBuffer:        make([]byte, 5*2),
		Raw:              append([]byte(nil), p.Raw...),
		policyIDs:        policyIDs,
		pathState:        common.NewFabridPathState(conf.ValidationRatio),
		getFabridKeys:    getFabridKeys,
	}

	// Get ingress/egress IFs and IAs from path interfaces
	for i, hop := range hops {
		if policyIDs[i] != nil {
			f.keys[hop.IA] = &drkey.FabridKey{}
		}
	}
	f.baseTimestamp = decoded.InfoFields[0].Timestamp
	if f.pathKey == nil {
		log.Debug("You are sending FABRID packets to a host inside an AS that does not " +
			"support FABRID. Path validation will only be available for the FABRID-enabled " +
			"on-path routers. Path validation at source won't be possible.")
	}
	return f, nil
}

func (f *FABRID) SetPath(s *slayers.SCION) error {
	var sp scion.Raw
	if err := sp.DecodeFromBytes(f.Raw); err != nil {
		return err
	}
	s.Path, s.PathType = &sp, sp.Type()
	return nil
}

func (f *FABRID) SetExtensions(s *slayers.SCION, p *snet.PacketInfo) error {
	if s == nil {
		return serrors.New("scion layer is nil")
	}
	if p == nil {
		return serrors.New("packet info is nil")
	}
	if f.getFabridKeys == nil {
		return serrors.New("drkey not correctly configured")
	}
	if p.HbhExtension == nil {
		p.HbhExtension = &slayers.HopByHopExtn{}
	}
	now := time.Now().Truncate(time.Millisecond)
	err := f.renewExpiredKeys(now)
	if err != nil {
		return serrors.WrapStr("While obtaining fabrid keys", err)
	}
	identifierOption := &extension.IdentifierOption{
		Timestamp:     now,
		BaseTimestamp: f.baseTimestamp,
		PacketID:      f.counter,
	}
	fabridOption := &extension.FabridOption{
		HopfieldMetadata: make([]*extension.FabridHopfieldMetadata, f.numHops),
	}
	for i := 0; i < f.numHops; i++ {
		meta := &extension.FabridHopfieldMetadata{}
		if f.policyIDs[i] != nil && f.keys[f.hops[i].IA] != nil {
			meta.FabridEnabled = true
			key := f.keys[f.hops[i].IA].Key
			encPolicyID, err := crypto.EncryptPolicyID(*f.policyIDs[i], identifierOption, key[:])
			if err != nil {
				return serrors.WrapStr("encrypting policy ID", err)
			}
			meta.EncryptedPolicyID = encPolicyID
		}
		fabridOption.HopfieldMetadata[i] = meta
	}
	valNumber, pathValReply, err := crypto.InitValidators(fabridOption, identifierOption, s,
		f.tmpBuffer, f.pathKey, f.keys, nil, f.hops)
	if err != nil {
		return serrors.WrapStr("initializing validators failed", err)
	}
	err = identifierOption.Serialize(f.identifierBuffer)
	if err != nil {
		return serrors.WrapStr("serializing identifier", err)
	}
	err = fabridOption.SerializeTo(f.fabridBuffer)
	if err != nil {
		return serrors.WrapStr("serializing fabrid option", err)
	}
	fabridLength := 4 + 4*f.numHops
	p.HbhExtension.Options = append(p.HbhExtension.Options,
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeIdentifier,
			OptData:      f.identifierBuffer,
			OptDataLen:   8,
			ActualLength: 8,
		},
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeFabrid,
			OptData:      f.fabridBuffer[:fabridLength],
			OptDataLen:   uint8(fabridLength),
			ActualLength: fabridLength,
		})

	// If the path key is nil, we assume the destination AS does not support FABRID.
	// So in that case we won't be able to receive any validation responses.
	// So validation at source won't be possible.
	if f.pathKey != nil {
		err = f.setControlOptionsExtensions(valNumber, pathValReply, identifierOption, p)
		if err != nil {
			return err
		}
	}
	f.counter++
	f.pathState.Stats.TotalPackets++
	return nil
}

func (f *FABRID) setControlOptionsExtensions(valNumber uint8, pathValReply uint32,
	identifierOption *extension.IdentifierOption, p *snet.PacketInfo) error {
	var err error
	if valNumber < f.pathState.ValidationRatio {
		err = f.pathState.StoreValidationResponse(pathValReply,
			identifierOption.GetRelativeTimestamp(),
			f.counter)
		if err != nil {
			return err
		}
	}

	var e2eOpts []*extension.FabridControlOption
	if f.pathState.UpdateValRatio {
		valConfigOption := extension.NewFabridControlOption(extension.ValidationConfig)
		err = valConfigOption.SetValidationRatio(f.pathState.ValidationRatio)
		if err != nil {
			return err
		}
		e2eOpts = append(e2eOpts, valConfigOption)
		f.pathState.UpdateValRatio = false
		log.Debug("FABRID control: outgoing validation config",
			"valRatio", f.pathState.ValidationRatio)
	}
	if f.pathState.RequestStatistics {
		statisticsRequestOption := &extension.FabridControlOption{
			Type: extension.StatisticsRequest,
			Auth: [4]byte{},
		}
		e2eOpts = append(e2eOpts, statisticsRequestOption)
		f.pathState.RequestStatistics = false
		log.Debug("FABRID control: sending statistics request")
	}
	if len(e2eOpts) > 0 {
		if p.E2eExtension == nil {
			p.E2eExtension = &slayers.EndToEndExtn{}
		}
		for i, replyOpt := range e2eOpts {
			err = crypto.InitFabridControlValidator(replyOpt, identifierOption, f.pathKey.Key[:])
			if err != nil {
				return err
			}
			buffer := f.e2eBuffer[i*5 : (i+1)*5]
			err = replyOpt.SerializeTo(buffer)
			if err != nil {
				return err
			}
			fabridReplyOptionLength := extension.BaseFabridControlLen +
				extension.FabridControlOptionDataLen(replyOpt.Type)
			p.E2eExtension.Options = append(p.E2eExtension.Options,
				&slayers.EndToEndOption{
					OptType:      slayers.OptTypeFabridControl,
					OptData:      buffer,
					OptDataLen:   uint8(fabridReplyOptionLength),
					ActualLength: fabridReplyOptionLength,
				})
		}
	}
	return nil
}

func (f *FABRID) HandleFabridControlOption(controlOption *extension.FabridControlOption,
	identifierOption *extension.IdentifierOption) error {

	err := crypto.VerifyFabridControlValidator(controlOption, identifierOption, f.pathKey.Key[:])
	if err != nil {
		return err
	}
	switch controlOption.Type {
	case extension.ValidationConfigAck:
		confirmedRatio, err := controlOption.ValidationRatio()
		if err != nil {
			return err
		}
		if confirmedRatio == f.pathState.ValidationRatio {
			log.Debug("FABRID control: validation ratio confirmed", "ratio", confirmedRatio)
		} else if confirmedRatio < f.pathState.ValidationRatio {
			log.Info("FABRID control: validation ratio reduced by server",
				"requested", f.pathState.ValidationRatio, "confirmed", confirmedRatio)
			f.pathState.ValidationRatio = confirmedRatio
		}
	case extension.ValidationResponse:
		err = f.pathState.CheckValidationResponse(controlOption)
		if err != nil {
			return err
		}
		err = f.conf.ValidationHandler(f.pathState, controlOption, true)
		if err != nil {
			return err
		}

	case extension.StatisticsResponse:
		totalPkts, invalidPkts, err := controlOption.Statistics()
		if err != nil {
			return err
		}
		log.Info("FABRID control: statistics response", "totalPackets", totalPkts,
			"invalidPackets", invalidPkts)
	}
	return nil
}

// This function iterates over all on-path ASes and checks whether the keys are still valid.
// If it finds expired keys it marks them as expired and renews all expired keys at once.
func (f *FABRID) renewExpiredKeys(t time.Time) error {
	var expiredAses []addr.IA = nil
	for ia, key := range f.keys {
		if key.Epoch.NotAfter.Before(t) {
			// key is expired, mark as expired
			if expiredAses == nil {
				expiredAses = make([]addr.IA, 0, len(f.keys))
			}
			expiredAses = append(expiredAses, ia)
		}
	}
	isPathKeyExpired := false
	if f.pathKey != nil {
		isPathKeyExpired = f.pathKey.Epoch.NotAfter.Before(t)
	}
	if expiredAses != nil || isPathKeyExpired {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		meta := drkey.FabridKeysMeta{
			SrcAS:    f.conf.LocalIA,
			SrcHost:  f.conf.LocalAddr,
			PathASes: expiredAses,
			DstAS:    f.conf.DestinationIA,
		}
		if isPathKeyExpired {
			meta.DstHost = &f.conf.DestinationAddr
		}
		keys, err := f.getFabridKeys(ctx, meta)
		if err != nil {
			return err
		}
		if isPathKeyExpired {
			f.pathKey = &keys.PathKey
		}
		for i := range keys.ASHostKeys {
			f.keys[keys.ASHostKeys[i].AS] = &keys.ASHostKeys[i]
		}
	}
	return nil
}
