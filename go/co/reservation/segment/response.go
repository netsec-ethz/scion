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

package segment

import (
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

type SegmentSetupResponse interface {
	isSegmentSetupResponse_Success_Failure()

	GetAuthenticators() [][]byte
	SetAuthenticator(currentStep int, authenticator []byte)
	Success() bool
	ToRaw(step int) []byte // returns the response serialized to the `step` node
	ToRawAllHFs() []byte
}

type SegmentSetupResponseSuccess struct {
	base.AuthenticatedResponse
	Token reservation.Token
}

func (*SegmentSetupResponseSuccess) isSegmentSetupResponse_Success_Failure() {}
func (*SegmentSetupResponseSuccess) Success() bool                           { return true }

// ToRaw returns the raw representation for this response.
// The step parameter indicates which step index along the path we want to serialize as.
// This means that, given a full success response back at the initiator AS, the initiator AS
// can obtain the raw representation as it was done in the step `step` (removing the
// hop fields added later).
// This function is always called when the caller AS has ALREADY added their hop field to the
// token. Invariant: len(hop_fields) == len(path)
// TODO(juagargi) this function belongs to the store package, who can control when to call it.
func (r *SegmentSetupResponseSuccess) ToRaw(step int) []byte {
	tokenLen := r.Token.Len() - (step * 8) // remove 8 bytes per HF that we won't serialize
	buff := make([]byte, 1+4+tokenLen)
	buff[0] = 0
	r.Serialize(buff[1:5])
	// the token must be serialized _as if_ this Response was located at step `step`:
	tok := reservation.Token{
		InfoField: r.Token.InfoField,
		HopFields: r.Token.GetFirstNHopFields(len(r.Token.HopFields) - step),
	}
	tok.Read(buff[5 : 5+tokenLen])
	return buff
}

// ToRawAllHFs returns the serialized version of this success response.
func (r *SegmentSetupResponseSuccess) ToRawAllHFs() []byte {
	return r.ToRaw(0)
}

type SegmentSetupResponseFailure struct {
	base.AuthenticatedResponse
	FailedStep    uint8
	FailedRequest *SetupReq
	Message       string
}

func (*SegmentSetupResponseFailure) isSegmentSetupResponse_Success_Failure() {}
func (*SegmentSetupResponseFailure) Success() bool                           { return false }
func (r *SegmentSetupResponseFailure) ToRaw(step int) []byte {
	buff := make([]byte, 1+4+r.FailedRequest.Len()+len(r.Message))
	buff[0] = 1
	r.Serialize(buff[1:5])
	r.FailedRequest.Serialize(buff[5:5+r.FailedRequest.Len()], base.SerializeImmutable)
	offset := 5 + r.FailedRequest.Len()
	copy(buff[offset:], []byte(r.Message))
	return buff
}
func (r *SegmentSetupResponseFailure) ToRawAllHFs() []byte {
	return r.ToRaw(1)
}
