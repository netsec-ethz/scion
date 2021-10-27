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
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/drkey"
	dkut "github.com/scionproto/scion/go/lib/drkey/drkeyutil"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

func createAuthsForBaseRequest(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	req *BaseRequest) error {

	keys, err := getKeys(ctx, conn, req)
	if err != nil {
		return err
	}

	// MAC and set authenticators inside request
	payload := make([]byte, minSizeBaseReq(req))
	serializeBaseRequest(payload, req)
	req.Authenticators, err = dkut.ComputeAuthenticators(payload, keys)
	return err
}

func createAuthsForE2EReservationSetup(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	req *E2EReservationSetup) error {

	keys, err := getKeys(ctx, conn, &req.BaseRequest)
	if err != nil {
		return err
	}

	payload := make([]byte, minSizeE2ESetupReq(req))
	serializeE2EReservationSetup(payload, req)
	req.Authenticators, err = dkut.ComputeAuthenticators(payload, keys)
	return err
}

func getKeys(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer, req *BaseRequest) ([][]byte, error) {
	if len(req.Path.Steps) < 2 {
		return nil, serrors.New("wrong path in request")
	}
	localIA := req.Path.Steps[0].IA
	ias := make([]addr.IA, len(req.Path.Steps)-1)
	for i := 1; i < len(req.Path.Steps); i++ {
		step := req.Path.Steps[i]
		ias[i-1] = step.IA
	}
	return dkut.GetLvl2Keys(ctx, conn, drkey.AS2Host, "colibri",
		dkut.SlowIAs(localIA), dkut.SlowHosts(addr.HostFromIP(req.SrcHost)),
		dkut.FastIAs(ias...))
}

func minSizeBaseReq(req *BaseRequest) int {
	return req.Id.Len() + 1 + 4 + // ID + index + time_stamp
		+req.Path.Len() + // path
		16 + 16 // srcHost + dstHost
}

func minSizeE2ESetupReq(req *E2EReservationSetup) int {
	// BaseRequest + BW + Segment reservation IDs
	return minSizeBaseReq(&req.BaseRequest) + 1 + len(req.Segments)*reservation.IDSegLen
}

func serializeBaseRequest(buff []byte, req *BaseRequest) {
	minSize := minSizeBaseReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minumum %d)",
		len(buff), minSize)
	offset := req.Id.Len()
	// ID, index and timestamp:
	req.Id.Read(buff[:offset]) // ignore errors (length was already checked)
	buff[offset] = byte(req.Index)
	offset++
	binary.BigEndian.PutUint32(buff[offset:], util.TimeToSecs(req.TimeStamp))
	offset += 4
	// path:
	req.Path.Serialize(buff[offset:], false)
	offset += req.Path.Len()
	// src and dst hosts:
	copy(buff[offset:], req.SrcHost.To16())
	offset += 16
	copy(buff[offset:], req.DstHost.To16())
}

func serializeE2EReservationSetup(buff []byte, req *E2EReservationSetup) {
	minSize := minSizeE2ESetupReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minumum %d)",
		len(buff), minSize)
	offset := minSizeBaseReq(&req.BaseRequest)
	serializeBaseRequest(buff[:offset], &req.BaseRequest)

	// BW and segments:
	buff[offset] = byte(req.RequestedBW)
	offset++
	for _, id := range req.Segments {
		id.Read(buff[offset:]) // ignore errors (length was already checked)
		offset += reservation.IDSegLen
	}
}
