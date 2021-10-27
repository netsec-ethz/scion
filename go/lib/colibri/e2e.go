// Copyright 2021 ETH Zurich
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

// Package colibri contains methods for the creation and verification of the colibri packet
// timestamp and validation fields.
package colibri

import (
	"context"
	"net"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	dkut "github.com/scionproto/scion/go/lib/drkey/drkeyutil"
)

// BaseRequest is used for every colibri request through sciond.
type BaseRequest struct {
	Id             reservation.ID
	Index          reservation.IndexNumber
	TimeStamp      time.Time // deleteme check this is translated, etc
	SrcHost        net.IP
	DstHost        net.IP
	Path           *base.TransparentPath // non nil path. It contains SrcIA and DstIA.
	Authenticators [][]byte              // per spec., MACs for AS_i on the immutable data
}

func (r *BaseRequest) CreateAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer) error {

	return createAuthsForBaseRequest(ctx, conn, r)
}

// E2EReservationSetup has the necessary data for an endhost to setup/renew an e2e reservation.
type E2EReservationSetup struct {
	BaseRequest
	RequestedBW reservation.BWCls
	Segments    []reservation.ID
}

func (r *E2EReservationSetup) CreateAuthenticators(ctx context.Context,
	conn dkut.DRKeyGetLvl2Keyer) error {

	return createAuthsForE2EReservationSetup(ctx, conn, r)
}

// deleteme TODO(juagargi) add a NewE2eReservationSetup function that simplifies the creation
// of the E2EReservationSetup (look at hellocolibri) and `git grep -n E2EReservationSetup` and use the new function.
type E2EResponseError struct {
	Message  string
	FailedAS int
}

func (e *E2EResponseError) Error() string {
	return e.Message
}

type E2ESetupError struct {
	E2EResponseError
	AllocationTrail []reservation.BWCls
}

// AdmissionEntry contains the fields which will be inserted into the admission list of the host
// specified by DstHost. If DstHost is empty, the apparent IP address of the connection
// between the scion daemon and the local COLIBRI service will be used.
// If DstHost is not empty, it will be checked against the IP of the connection between the
// scion daemon and the local COLIBRI service.
// The value ValidUntil specifies the point in time when this entry will no longer be valid.
// Expired (non valid) entries are deleted automatically.
// If during admission more than one entry in the admission list match the request/renewal,
// only the newest one will be considered.
type AdmissionEntry struct {
	DstHost net.IP // the owner of this admission list. If empty, the IP from
	//                the TCP connection from the daemon to the service will be used
	ValidUntil      time.Time // requested validity of the entry
	RegexpIA        string
	RegexpHost      string
	AcceptAdmission bool
}
