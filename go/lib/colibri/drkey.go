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
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"time"

	"github.com/dchest/cmac"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/util"
)

// DRKeyGetter is the interface used to obtain AS-Host DRKeys. Usually this is just the daemon.
type DRKeyGetter interface {
	DRKeyGetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
}

func createAuthsForBaseRequest(ctx context.Context, conn DRKeyGetter,
	req *BaseRequest, steps base.PathSteps) error {

	keys, err := getKeys(ctx, conn, steps, req.SrcHost, req.TimeStamp)
	if err != nil {
		return err
	}

	// MAC and set authenticators inside request
	payload := make([]byte, minSizeBaseReq(req))
	serializeBaseRequest(payload, req)

	req.Authenticators, err = computeAuthenticators(payload, keys)
	return err
}

func createAuthsForE2EReservationSetup(ctx context.Context, conn DRKeyGetter,
	req *E2EReservationSetup) error {

	keys, err := getKeys(ctx, conn, req.Steps, req.SrcHost, req.TimeStamp)
	if err != nil {
		return err
	}

	payload := make([]byte, minSizeE2ESetupReq(req))
	serializeE2EReservationSetup(payload, req)
	req.Authenticators, err = computeAuthenticators(payload, keys)
	return err
}

func validateResponseAuthenticators(ctx context.Context, conn DRKeyGetter,
	res *E2EResponse, steps base.PathSteps, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, steps); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, steps); err != nil {
		return err
	}
	payloads, err := serializeResponse(res, steps, reqTimestamp)
	if err != nil {
		return err
	}
	return validateBasic(ctx, conn, payloads, res.Authenticators,
		steps, srcHost, reqTimestamp)
}

func validateResponseErrorAuthenticators(ctx context.Context, conn DRKeyGetter,
	res *E2EResponseError, steps base.PathSteps, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, steps); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, steps); err != nil {
		return err
	}
	// because a failure can originate at any on-path-AS, skip ASes before its origin:
	originalAuthenticators := res.Authenticators
	originalSteps := steps
	defer func() {
		res.Authenticators = originalAuthenticators
		steps = originalSteps
	}()
	res.Authenticators = res.Authenticators[:res.FailedAS+1]
	steps = steps[:res.FailedAS+1]
	payloads := serializeResponseError(res, reqTimestamp)
	return validateBasic(ctx, conn, payloads, res.Authenticators,
		steps, srcHost, reqTimestamp)
}

func validateSetupErrorAuthenticators(ctx context.Context, conn DRKeyGetter,
	res *E2ESetupError, steps base.PathSteps, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, steps); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, steps); err != nil {
		return err
	}
	// because a failure can originate at any on-path AS, skip ASes before its origin:
	originalAuthenticators := res.Authenticators
	originalSteps := steps.Copy()
	defer func() {
		res.Authenticators = originalAuthenticators
		steps = originalSteps
	}()
	res.Authenticators = res.Authenticators[:res.FailedAS+1]
	steps = steps[:res.FailedAS+1]
	payloads := serializeSetupError(res, reqTimestamp)
	return validateBasic(ctx, conn, payloads, res.Authenticators,
		steps, srcHost, reqTimestamp)
}

func getKeys(ctx context.Context, conn DRKeyGetter, steps []base.PathStep,
	srcHost net.IP, valTime time.Time) ([]drkey.Key, error) {

	if len(steps) < 2 {
		return nil, serrors.New("wrong path in request")
	}
	return getKeysWithLocalIA(ctx, conn, steps[1:], steps[0].IA, srcHost, valTime)
}

func getKeysWithLocalIA(ctx context.Context, conn DRKeyGetter, steps []base.PathStep,
	localIA addr.IA, host net.IP, valtime time.Time) ([]drkey.Key, error) {

	keys := make([]drkey.Key, len(steps))
	for i, step := range steps {
		key, err := conn.DRKeyGetASHostKey(ctx,
			drkey.ASHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId:  drkey.COLIBRI,
					Validity: valtime,
					SrcIA:    step.IA,
					DstIA:    localIA,
				},
				DstHost: host.String(),
			})
		if err != nil {
			return nil, err
		}
		keys[i] = key.Key
	}
	return keys, nil
}

func minSizeBaseReq(req *BaseRequest) int {
	// fail to compile if these fields are not there
	_ = req.Id
	_ = req.Index
	_ = req.TimeStamp
	_ = req.SrcHost
	_ = req.DstHost
	return (6 + reservation.IDSuffixE2ELen) + 1 + 4 + // ID + index + time_stamp
		16 + 16 // srcHost + dstHost
}

func minSizeE2ESetupReq(req *E2EReservationSetup) int {
	// fail to compile if these fields are not there
	_ = req.BaseRequest
	_ = req.RequestedBW
	_ = req.Segments
	// BaseRequest + BW + Segment reservation IDs + Steps
	return minSizeBaseReq(&req.BaseRequest) +
		1 + len(req.Segments)*reservation.IDSegLen + req.Steps.Size()
}

func serializeBaseRequest(buff []byte, req *BaseRequest) {
	minSize := minSizeBaseReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minimum %d)",
		len(buff), minSize)
	offset := req.Id.Len()
	// ID, index and timestamp:
	req.Id.Read(buff[:offset]) // ignore errors (length was already checked)
	buff[offset] = byte(req.Index)
	offset++
	binary.BigEndian.PutUint32(buff[offset:], util.TimeToSecs(req.TimeStamp))
	offset += 4
	// src and dst hosts:
	copy(buff[offset:], req.SrcHost.To16())
	offset += 16
	copy(buff[offset:], req.DstHost.To16())
}

func serializeE2EReservationSetup(buff []byte, req *E2EReservationSetup) {
	minSize := minSizeE2ESetupReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minimum %d)",
		len(buff), minSize)
	offset := minSizeBaseReq(&req.BaseRequest)
	serializeBaseRequest(buff[:offset], &req.BaseRequest)

	// steps:
	req.Steps.Serialize(buff[offset:])
	offset += req.Steps.Size()

	// BW and segments:
	buff[offset] = byte(req.RequestedBW)
	offset++
	for _, id := range req.Segments {
		id.Read(buff[offset:]) // ignore errors (length was already checked)
		offset += reservation.IDSegLen
	}
}

// serializeResponse returns the serialized versions of the response, one per AS in the path.
func serializeResponse(res *E2EResponse, steps base.PathSteps, timestamp time.Time) (
	[][]byte, error) {

	colPath, ok := res.ColibriPath.Dataplane().(snetpath.Colibri)
	if !ok {
		return nil, serrors.New("unsupported non colibri path type",
			"path_type", common.TypeOf(res.ColibriPath.Dataplane()))
	}

	colibriPath, err := colPath.ToColibriPath()
	if err != nil {
		return nil, serrors.WrapStr("received invalid colibri path", err)
	}

	timestampBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(timestampBuff, util.TimeToSecs(timestamp))
	allHfs := colibriPath.HopFields
	payloads := make([][]byte, len(allHfs))
	for i := range steps {
		colibriPath.InfoField.HFCount = uint8(len(allHfs) - i)
		colibriPath.HopFields = allHfs[i:]
		payloads[i] = make([]byte, 1+4+colibriPath.Len()) // marker + timestamp + path
		payloads[i][0] = 0                                // success marker
		copy(payloads[i][1:5], timestampBuff)
		// TODO(juagargi) why are we serializing the transport path???
		if err := colibriPath.SerializeTo(payloads[i][5:]); err != nil {
			return nil, err
		}
	}
	return payloads, nil
}

// serializeResponseError serializes the response error and returns one payload per AS in the path.
func serializeResponseError(res *E2EResponseError, timestamp time.Time) [][]byte {
	message := ([]byte(res.Message))
	// failure marker + timestamp + failedAS (as uint8) + message
	payload := make([]byte, 1+4+1+len(message))
	payload[0] = 1 // failure marker
	binary.BigEndian.PutUint32(payload[1:5], util.TimeToSecs(timestamp))
	payload[5] = uint8(res.FailedAS)
	copy(payload[6:], message)

	payloads := make([][]byte, len(res.Authenticators))
	for i := range payloads {
		payloads[i] = payload
	}
	return payloads
}

// serializeSetupError serializes the setup error and returns one payload per AS in the path.
func serializeSetupError(res *E2ESetupError, timestamp time.Time) [][]byte {
	message := ([]byte(res.Message))
	// failure marker + timestamp + failedAS (as uint8) + message
	payload := make([]byte, 1+4+1+len(message))
	payload[0] = 1 // failure marker
	binary.BigEndian.PutUint32(payload[1:5], util.TimeToSecs(timestamp))
	payload[5] = uint8(res.FailedAS)
	copy(payload[6:], message)

	payloads := make([][]byte, len(res.Authenticators))
	for i := range payloads {
		trail := res.AllocationTrail[i:]
		// append trail to payload (convoluted due to the type cast to byte):
		payloads[i] = append(payload, make([]byte, len(trail))...)
		for j := range trail {
			payloads[i][len(payload)+j] = byte(trail[j])
		}
	}
	return payloads
}

func validateBasic(ctx context.Context, conn DRKeyGetter, payloads [][]byte,
	authenticators [][]byte, steps base.PathSteps,
	srcHost net.IP, valTime time.Time) error {

	keys, err := getKeysWithLocalIA(ctx, conn, steps,
		steps.SrcIA(), srcHost, valTime)
	if err != nil {
		return err
	}

	ok, err := validateAuthenticators(payloads, keys, authenticators)
	if err != nil {
		return err
	}
	if !ok {
		return serrors.New("validation failed for response")
	}
	return nil
}

func checkValidAuthenticatorsAndPath(res interface{}, steps base.PathSteps) error {
	if res == nil {
		return serrors.New("no response")
	}
	if steps == nil {
		return serrors.New("no path")
	}
	return nil
}

func checkEqualLength(authenticators [][]byte, steps base.PathSteps) error {
	if len(steps) != len(authenticators) {
		return serrors.New("wrong lengths: |path| != |authenticators|",
			"path", len(steps), "authenticators", len(authenticators))
	}
	return nil
}

// ComputeAuthenticators returns the authenticators obtained to apply a MAC function to the
// same payload.
func computeAuthenticators(payload []byte, keys []drkey.Key) ([][]byte, error) {
	auths := make([][]byte, len(keys))
	for i, k := range keys {
		var err error
		auths[i], err = computeMAC(payload, k)
		if err != nil {
			return nil, err
		}
	}
	return auths, nil
}

// ValidateAuthenticators validates each authenticators[i] against MAC(payload[i], keys[i]).
// Returns error if the MAC function returns any error, or true/false if each of the authenticators
// matches the result of each MAC function invocation.
func validateAuthenticators(payloads [][]byte, keys []drkey.Key, authenticators [][]byte) (
	bool, error) {

	if len(payloads) != len(keys) || len(keys) != len(authenticators) {
		return false, serrors.New("wrong lengths (must be the same)")
	}
	for i := range keys {
		mac, err := computeMAC(payloads[i], keys[i])
		if err != nil {
			return false, serrors.WrapStr("MAC function", err)
		}
		if subtle.ConstantTimeCompare(mac, authenticators[i]) != 1 {
			return false, nil
		}
	}
	return true, nil
}

func computeMAC(payload []byte, key drkey.Key) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, serrors.WrapStr("initializing aes cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("initializing cmac", err)
	}
	_, err = mac.Write(payload)
	if err != nil {
		return nil, serrors.WrapStr("preparing mac", err)
	}
	return mac.Sum(nil), nil
}
