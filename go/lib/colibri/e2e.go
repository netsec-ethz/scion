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
	"crypto/rand"
	"net"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	dkut "github.com/scionproto/scion/go/lib/drkey/drkeyutil"
	"github.com/scionproto/scion/go/lib/snet"
)

// BaseRequest is used for every colibri request through sciond.
type BaseRequest struct {
	Id             reservation.ID
	Index          reservation.IndexNumber
	TimeStamp      time.Time
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

// NewReservation creates a new E2EReservationSetup, including the authenticator fields.
func NewReservation(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	fullTrip *FullTrip, srcHost, dstHost net.IP,
	requestedBW reservation.BWCls) (*E2EReservationSetup, error) {

	p := fullTrip.Path()
	setupReq := &E2EReservationSetup{
		BaseRequest: BaseRequest{
			Id: reservation.ID{
				ASID:   p.SrcIA().AS(),
				Suffix: make([]byte, 12),
			},
			Index:     0, // new index
			TimeStamp: time.Now(),
			SrcHost:   srcHost,
			DstHost:   dstHost,
			Path:      p,
		},
		RequestedBW: requestedBW,
		Segments:    fullTrip.Segments(),
	}
	rand.Read(setupReq.Id.Suffix) // random suffix
	err := setupReq.CreateAuthenticators(ctx, conn)
	return setupReq, err
}

// E2EResponse is the response returned by setting up a colibri reservation. See also daemon.
type E2EResponse struct {
	Authenticators [][]byte
	ColibriPath    snet.Path
}

// ValidateAuthenticators returns nil if the source validation for all hops succeeds.
func (r *E2EResponse) ValidateAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	requestPath *base.TransparentPath, srcHost net.IP, requestTimestamp time.Time) error {

	return validateResponseAuthenticators(ctx, conn, r, requestPath, srcHost, requestTimestamp)
}

type E2EResponseError struct {
	Authenticators [][]byte
	FailedAS       int
	Message        string
}

func (e *E2EResponseError) Error() string {
	return e.Message
}

func (r *E2EResponseError) ValidateAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	requestPath *base.TransparentPath, srcHost net.IP, requestTimestamp time.Time) error {

	return validateResponseErrorAuthenticators(ctx, conn, r, requestPath, srcHost, requestTimestamp)
}

type E2ESetupError struct {
	E2EResponseError
	AllocationTrail []reservation.BWCls
}

func (r *E2ESetupError) ValidateAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	requestPath *base.TransparentPath, srcHost net.IP, requestTimestamp time.Time) error {

	return validateSetupErrorAuthenticators(ctx, conn, r, requestPath, srcHost, requestTimestamp)
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
