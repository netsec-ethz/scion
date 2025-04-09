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

package common

import (
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/extension"
)

type Statistics struct {
	TotalPackets   uint32
	InvalidPackets uint32
}

type validationIdentifier struct {
	timestamp uint32
	packetId  uint32
}

type PathState struct {
	ValidationRatio      uint8
	UpdateValRatio       bool
	RequestStatistics    bool
	Stats                Statistics
	expectedValResponses map[validationIdentifier]uint32
}

func NewFabridPathState(valRatio uint8) *PathState {
	state := &PathState{
		ValidationRatio:      valRatio,
		UpdateValRatio:       true,
		RequestStatistics:    false,
		expectedValResponses: make(map[validationIdentifier]uint32),
	}
	return state
}

func (ps *PathState) StoreValidationResponse(validator uint32,
	timestamp uint32, packetID uint32) error {
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	_, found := ps.expectedValResponses[valIdent]
	if found {
		return serrors.New("Validation response already stored", "validationIdentifier", valIdent)
	}
	log.Debug("Storing validation response", "packetID", packetID, "timestamp", timestamp)
	ps.expectedValResponses[valIdent] = validator
	return nil
}

func (ps *PathState) CheckValidationResponse(fco *extension.FabridControlOption) error {
	timestamp, err := fco.Timestamp()
	if err != nil {
		return err
	}
	packetID, err := fco.PacketID()
	if err != nil {
		return err
	}
	validatorReply, err := fco.PathValidatorReply()
	if err != nil {
		return err
	}
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	log.Debug("Checking validation response", "timestamp", timestamp, "packetID", packetID)
	validatorStored, found := ps.expectedValResponses[valIdent]
	if !found {
		return serrors.New("Unknown validation response", "validationIdentifier", valIdent)
	}
	if validatorStored != validatorReply {
		return serrors.New("Wrong path validation response", "validationIdentifier", valIdent,
			"expected", validatorStored, "actual", validatorReply)
	}
	return nil
}
