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
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

type SetupResponse interface {
	isSegmentSetupResponse_Success_Failure()
}

type SetupResponseSuccess struct {
	base.AuthenticatedResponse
	Token []byte
}

func (*SetupResponseSuccess) isSegmentSetupResponse_Success_Failure() {}

type SetupResponseFailure struct {
	base.AuthenticatedResponse
	Message    string
	FailedStep uint8
	AllocTrail []reservation.BWCls
}

func (*SetupResponseFailure) isSegmentSetupResponse_Success_Failure() {}
