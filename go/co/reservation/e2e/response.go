// Copyright 2020 ETH Zurich, Anapaya Systems
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

package e2e

import (
	"net"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

type SetupResponse interface {
	isSegmentSetupResponse_Success_Failure()

	ToRaw(step int, rsvID *reservation.ID) ([]byte, error)
	SetAuthenticator(currentStep int, authenticator []byte)
	GetTimestamp() time.Time
}

type SetupResponseSuccess struct {
	base.AuthenticatedResponse // these authenticators have the same size as the path
	Token                      []byte
}

func (*SetupResponseSuccess) isSegmentSetupResponse_Success_Failure() {}
func (r *SetupResponseSuccess) ToRaw(step int, rsvID *reservation.ID) ([]byte, error) {
	tok, err := reservation.TokenFromRaw(r.Token)
	if err != nil {
		return nil, serrors.WrapStr("loading token", err)
	}
	colPath := DeriveColibriPath(rsvID, 0, net.IPv4(0, 0, 0, 0), 0, net.IPv4(0, 0, 0, 0), tok)
	colPath.InfoField.HFCount = uint8(len(colPath.HopFields))

	// marker + authenticated response + path
	buff := make([]byte, 1+4+colPath.Len())
	buff[0] = 0 // success marker
	r.AuthenticatedResponse.Serialize(buff[1:5])
	err = colPath.SerializeTo(buff[5:])
	return buff, err
}

// SetAuthenticator expects to have the same amount of authenticators as steps in the path.
func (r *SetupResponseSuccess) SetAuthenticator(step int, authenticator []byte) {
	r.Authenticators[step] = authenticator
}

func (r *SetupResponseSuccess) GetTimestamp() time.Time {
	return r.Timestamp
}

type SetupResponseFailure struct {
	base.AuthenticatedResponse
	FailedStep uint8
	Message    string
	AllocTrail []reservation.BWCls
}

func (*SetupResponseFailure) isSegmentSetupResponse_Success_Failure() {}
func (r *SetupResponseFailure) ToRaw(step int, rsvID *reservation.ID) ([]byte, error) {
	messageBytes := ([]byte)(r.Message)
	// marker + AuthenticatedResponse + FailedStep + Message + AllocTrail
	buff := make([]byte, 1+4+1+len(messageBytes)+len(r.AllocTrail)-step)
	buff[0] = 1 // failure marker
	offset := 5
	r.AuthenticatedResponse.Serialize(buff[1:offset])
	buff[offset] = r.FailedStep
	offset++
	copy(buff[offset:], ([]byte)(messageBytes))
	offset += len(messageBytes)
	for _, bw := range r.AllocTrail[step:] {
		buff[offset] = byte(bw)
		offset++
	}
	return buff, nil
}

// SetAuthenticator expects to have the same amount of authenticators as steps in the path.
func (r *SetupResponseFailure) SetAuthenticator(step int, authenticator []byte) {
	r.Authenticators[step] = authenticator
}

func (r *SetupResponseFailure) GetTimestamp() time.Time {
	return r.Timestamp
}
