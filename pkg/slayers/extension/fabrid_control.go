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

// The FABRID control option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr     |     ExtLen    |  OptType = 5  |    OptLen     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Type   |               E2E Mac                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                               |
// |                          [Content]                            |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package extension

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const BaseFabridControlLen int = 4

type FabridControlOptionType uint8

// Definition of FABRID control option type constants
const (
	ValidationConfig FabridControlOptionType = iota
	ValidationConfigAck
	ValidationResponse
	StatisticsRequest
	StatisticsResponse
)

type FabridControlOption struct {
	// Type of the control message
	Type FabridControlOptionType
	// E2E MAC of the option content
	Auth [4]byte
	Data []byte
}

func NewFabridControlOption(t FabridControlOptionType) *FabridControlOption {
	return &FabridControlOption{
		Type: t,
		Auth: [4]byte{},
		Data: make([]byte, BaseFabridControlLen+FabridControlOptionDataLen(t)),
	}
}

// Validates the length of FabridControlOption. Requires Type to be set
func (fc *FabridControlOption) validate(b []byte) error {
	if fc == nil {
		return serrors.New("Fabrid control option must not be nil")
	}
	if fc.Type > StatisticsResponse {
		return serrors.New("Invalid fabrid control option type")
	}
	if len(b) < BaseFabridControlLen+FabridControlOptionDataLen(fc.Type) {
		return serrors.New("Raw Fabrid control option too short", "is", len(b),
			"expected", BaseFabridControlLen+FabridControlOptionDataLen(fc.Type))
	}
	return nil
}

func (fc *FabridControlOption) Decode(b []byte) error {
	fc.Type = FabridControlOptionType(b[0] >> 4)
	if err := fc.validate(b); err != nil {
		return err
	}
	copy(fc.Auth[:], b[0:4])
	fc.Auth[0] &= 0xF

	fc.Data = make([]byte, FabridControlOptionDataLen(fc.Type))
	copy(fc.Data[:], b[4:4+FabridControlOptionDataLen(fc.Type)])
	return nil
}

func (fc *FabridControlOption) SerializeTo(b []byte) error {
	if fc == nil {
		return serrors.New("Fabrid control option must not be nil")
	}
	if len(b) < BaseFabridControlLen+FabridControlOptionDataLen(fc.Type) {
		return serrors.New("Buffer too short", "is", len(b),
			"expected", BaseFabridControlLen+FabridControlOptionDataLen(fc.Type))
	}
	// Set authenticator before type, so it is not overwritten
	copy(b[0:4], fc.Auth[:])
	b[0] &= 0xF // clear the first 4 (left) bits
	b[0] |= uint8(fc.Type) << 4
	if len(fc.Data) < FabridControlOptionDataLen(fc.Type) {
		return serrors.New("Data too short", "is", len(fc.Data),
			"expected", FabridControlOptionDataLen(fc.Type))
	}

	copy(b[4:], fc.Data[:FabridControlOptionDataLen(fc.Type)])
	return nil
}

// Getter and Setter functions

func (fc *FabridControlOption) Timestamp() (uint32, error) {
	switch fc.Type {
	case ValidationConfigAck, ValidationResponse, StatisticsResponse:
		return binary.BigEndian.Uint32(fc.Data[:4]), nil
	case ValidationConfig, StatisticsRequest:
		return 0, serrors.New("Wrong option type",
			"expected", string(ValidationConfigAck)+", "+string(ValidationResponse)+
				" or "+string(StatisticsResponse), "actual", fc.Type)
	}
	return 0, serrors.New("Invalid fabrid control option type", "type", fc.Type)
}

func (fc *FabridControlOption) SetTimestamp(timestamp uint32) error {
	switch fc.Type {
	case ValidationConfigAck, ValidationResponse, StatisticsResponse:
		binary.BigEndian.PutUint32(fc.Data[:4], timestamp)
		return nil
	case ValidationConfig, StatisticsRequest:
		return serrors.New("Wrong option type",
			"expected", string(ValidationConfigAck)+", "+string(ValidationResponse)+
				" or "+string(StatisticsResponse), "actual", fc.Type)
	}
	return serrors.New("Invalid fabrid control option type", "type", fc.Type)
}

func (fc *FabridControlOption) PacketID() (uint32, error) {
	switch fc.Type {
	case ValidationConfigAck, ValidationResponse, StatisticsResponse:
		return binary.BigEndian.Uint32(fc.Data[4:8]), nil
	case ValidationConfig, StatisticsRequest:
		return 0, serrors.New("Wrong option type",
			"expected", string(ValidationConfigAck)+", "+string(ValidationResponse)+
				" or "+string(StatisticsResponse), "actual", fc.Type)
	}
	return 0, serrors.New("Invalid fabrid control option type", "type", fc.Type)
}

func (fc *FabridControlOption) SetPacketID(packetID uint32) error {
	switch fc.Type {
	case ValidationConfigAck, ValidationResponse, StatisticsResponse:
		binary.BigEndian.PutUint32(fc.Data[4:8], packetID)
		return nil
	case ValidationConfig, StatisticsRequest:
		return serrors.New("Wrong option type",
			"expected", string(ValidationConfigAck)+", "+string(ValidationResponse)+
				" or "+string(StatisticsResponse), "actual", fc.Type)
	}
	return serrors.New("Invalid fabrid control option type", "type", fc.Type)
}

func (fc *FabridControlOption) ValidationRatio() (uint8, error) {
	if fc.Type == ValidationConfig {
		return fc.Data[0], nil
	} else if fc.Type == ValidationConfigAck {
		return fc.Data[8], nil
	}
	return 0, serrors.New("Wrong option type",
		"expected", string(ValidationConfig)+" or "+string(ValidationConfigAck), "actual", fc.Type)
}

func (fc *FabridControlOption) SetValidationRatio(valRatio uint8) error {
	if fc.Type == ValidationConfig {
		fc.Data[0] = valRatio
		return nil
	} else if fc.Type == ValidationConfigAck {
		fc.Data[8] = valRatio
		return nil
	}
	return serrors.New("Wrong option type",
		"expected", string(ValidationConfig)+" or "+string(ValidationConfigAck), "actual", fc.Type)
}

func (fc *FabridControlOption) PathValidatorReply() (uint32, error) {
	if fc.Type == ValidationResponse {
		return binary.BigEndian.Uint32(fc.Data[8:12]), nil
	}
	return 0, serrors.New("Wrong option type", "expected", ValidationResponse, "actual", fc.Type)
}

func (fc *FabridControlOption) SetPathValidatorReply(pathValReply uint32) error {
	if fc.Type == ValidationResponse {
		binary.BigEndian.PutUint32(fc.Data[8:12], pathValReply)
		return nil
	}
	return serrors.New("Wrong option type", "expected", ValidationResponse, "actual", fc.Type)
}

func (fc *FabridControlOption) Statistics() (uint32, uint32, error) {
	if fc.Type == StatisticsResponse {
		return binary.BigEndian.Uint32(fc.Data[8:12]), binary.BigEndian.Uint32(fc.Data[12:16]), nil
	}
	return 0, 0, serrors.New("Wrong option type", "expected", StatisticsResponse, "actual", fc.Type)
}

func (fc *FabridControlOption) SetStatistics(totalPackets uint32, invalidPackets uint32) error {
	if fc.Type == StatisticsResponse {
		binary.BigEndian.PutUint32(fc.Data[8:12], totalPackets)
		binary.BigEndian.PutUint32(fc.Data[12:16], invalidPackets)
		return nil
	}
	return serrors.New("Wrong option type", "expected", StatisticsResponse, "actual", fc.Type)
}

func FabridControlOptionDataLen(controlOptionType FabridControlOptionType) int {
	switch controlOptionType {
	case ValidationConfig:
		return 1
	case ValidationConfigAck:
		return 9
	case ValidationResponse:
		return 12
	case StatisticsRequest:
		return 0
	case StatisticsResponse:
		return 16
	default:
		return 0
	}
}

func ParseFabridControlOption(o *slayers.EndToEndOption) (*FabridControlOption, error) {
	if o.OptType != slayers.OptTypeFabridControl {
		return nil,
			serrors.New("Wrong option type", "expected", slayers.OptTypeFabridControl,
				"actual", o.OptType)
	}
	fc := &FabridControlOption{}
	if err := fc.Decode(o.OptData); err != nil {
		return nil, err
	}
	return fc, nil
}
