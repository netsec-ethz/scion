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
	ToRaw() []byte
}

type SegmentSetupResponseSuccess struct {
	base.AuthenticatedResponse
	Token reservation.Token
}

func (*SegmentSetupResponseSuccess) isSegmentSetupResponse_Success_Failure() {}
func (*SegmentSetupResponseSuccess) Success() bool                           { return true }
func (r *SegmentSetupResponseSuccess) ToRaw() []byte {
	buff := make([]byte, 1+4+r.Token.Len())
	buff[0] = 0
	r.Serialize(buff[1:5])
	r.Token.Read(buff[5:])
	return buff
}

type SegmentSetupResponseFailure struct {
	base.AuthenticatedResponse
	FailedRequest *SetupReq
	Message       string
}

func (*SegmentSetupResponseFailure) isSegmentSetupResponse_Success_Failure() {}
func (*SegmentSetupResponseFailure) Success() bool                           { return false }
func (r *SegmentSetupResponseFailure) ToRaw() []byte {
	buff := make([]byte, 1+4+r.FailedRequest.Len()+len(r.Message))
	buff[0] = 1
	r.Serialize(buff[1:5])
	r.FailedRequest.Serialize(buff[5:5+r.FailedRequest.Len()], base.SerializeImmutable)
	offset := 5 + r.FailedRequest.Len()
	copy(buff[offset:], []byte(r.Message))
	return buff
}
