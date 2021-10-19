// Copyright 2021 ETH Zurich, Anapaya Systems
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

package reservationstore

import (
	"context"
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dchest/cmac"
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

type Authenticator interface {
	macComputer
	macVerifier
}

type macComputer interface {
	// ComputeRequestInitialMAC computes the MAC for the immutable fields of the basic request,
	// for each AS in transit. This MAC is only computed at the first AS.
	// The inital AS is obtained from the first step of the path of the request.
	ComputeRequestInitialMAC(ctx context.Context, req *base.Request) error
	// SegmentRequestInitialMAC computes the MAC for the immutable fields of the setup request,
	// for each AS in transit. This MAC is only computed at the first AS.
	// The initial AS is obtained from the first step of the path of the request.
	ComputeSegmentSetupRequestInitialMAC(ctx context.Context, req *segment.SetupReq) error

	// ComputeE2eSetupRequestInitialMAC computes the MAC for the immutable fields of the setup
	// request, for each AS in transit. This MAC is only computed at the initiator host.
	// The initiator host is taken from the src host of the request.
	ComputeE2eSetupRequestInitialMAC(ctx context.Context, req *e2e.SetupReq) error

	ComputeRequestTransitMAC(ctx context.Context, req *base.Request) error

	ComputeSegmentSetupRequestTransitMAC(ctx context.Context, req *segment.SetupReq) error

	ComputeE2eSetupRequestTransitMAC(ctx context.Context, req *e2e.SetupReq) error
}

type macVerifier interface {
	// ValidateRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateRequest(ctx context.Context, req *base.Request) (bool, error)
	// ValidateSegSetupRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateSegSetupRequest(ctx context.Context, req *segment.SetupReq) (bool, error)
	// ValidateE2eSetupRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateE2eSetupRequest(ctx context.Context, req *e2e.SetupReq) (bool, error)
}

// DrkeyAuthenticator implements macComputer and macVerifier using DRKey.
type DrkeyAuthenticator struct {
	localIA   addr.IA
	connector daemon.Connector // to obtain level 1 & 2 keys
}

func NewDrkeyAuthenticator(localIA addr.IA, connector daemon.Connector) Authenticator {
	return &DrkeyAuthenticator{
		localIA:   localIA,
		connector: connector,
	}
}

func (a *DrkeyAuthenticator) ComputeRequestInitialMAC(ctx context.Context,
	req *base.Request) error {

	payload := make([]byte, req.ID.Len()+1+4)
	inputInitialBaseRequest(payload, req)
	return a.computeInitialMACforPayloadWithSegKeys(ctx, payload, req)
}

func (a *DrkeyAuthenticator) ComputeSegmentSetupRequestInitialMAC(ctx context.Context,
	req *segment.SetupReq) error {

	payload := inputInitialSegSetupRequest(req)
	return a.computeInitialMACforPayloadWithSegKeys(ctx, payload, &req.Request)
}

func (a *DrkeyAuthenticator) ComputeE2eSetupRequestInitialMAC(ctx context.Context,
	req *e2e.SetupReq) error {

	payload := inputInitialE2eSetupRequest(req)
	return a.computeInitialMACforPayloadWithE2eKeys(ctx, payload, req)
}

func (a *DrkeyAuthenticator) ComputeRequestTransitMAC(ctx context.Context,
	req *base.Request) error {

	if req.IsFirstAS() || req.IsLastAS() {
		return nil
	}
	payload := inputTransitSegRequest(req)
	return a.computeTransitMACforPayload(ctx, payload, req)
}

func (a *DrkeyAuthenticator) ComputeSegmentSetupRequestTransitMAC(ctx context.Context,
	req *segment.SetupReq) error {

	if req.IsFirstAS() || req.IsLastAS() {
		return nil
	}
	payload := inputTransitSegSetupRequest(req)
	return a.computeTransitMACforPayload(ctx, payload, &req.Request)
}

func (a *DrkeyAuthenticator) ComputeE2eSetupRequestTransitMAC(ctx context.Context,
	req *e2e.SetupReq) error {

	if req.IsFirstAS() || req.IsLastAS() {
		return nil
	}
	// deleteme: implement
	return nil
}

func (a *DrkeyAuthenticator) ValidateRequest(ctx context.Context,
	req *base.Request) (bool, error) {

	immutableInput := make([]byte, req.ID.Len()+1+4)
	inputInitialBaseRequest(immutableInput, req)
	ok, err := a.validateSegmentPayloadInitialMAC(ctx, req, immutableInput)
	if err == nil && ok && req.IsLastAS() {
		ok, err = a.validateRequestAtDestination(ctx, req)
	}
	return ok, err
}

func (a *DrkeyAuthenticator) ValidateSegSetupRequest(ctx context.Context,
	req *segment.SetupReq) (bool, error) {

	if req.IsFirstAS() {
		return true, nil
	}
	ok, err := a.validateSegmentPayloadInitialMAC(ctx, &req.Request, inputInitialSegSetupRequest(req))
	if err == nil && ok && req.IsLastAS() {
		ok, err = a.validateSegmentSetupRequestAtDestination(ctx, req)
	}
	return ok, err
}

func (a *DrkeyAuthenticator) ValidateE2eSetupRequest(ctx context.Context,
	req *e2e.SetupReq) (bool, error) {

	// TODO(juagargi) deleteme: implement
	return false, nil

}

func (a *DrkeyAuthenticator) validateRequestAtDestination(ctx context.Context, req *base.Request) (
	bool, error) {

	return a.validateAtDestination(ctx, req, func(i int) []byte {
		return inputTransitSegRequest(req)
	})
}

func (a *DrkeyAuthenticator) validateSegmentSetupRequestAtDestination(ctx context.Context,
	req *segment.SetupReq) (bool, error) {

	return a.validateAtDestination(ctx, &req.Request, func(i int) []byte {
		return inputTransitSegSetupRequestForStep(req, i)
	})
}

func (a *DrkeyAuthenticator) validateSegmentPayloadInitialMAC(ctx context.Context,
	req *base.Request, immutableInput []byte) (bool, error) {

	key, err := a.getDRKeyAS2AS(ctx, a.localIA, req.Path.SrcIA())
	if err != nil {
		return false, serrors.WrapStr("obtaining drkey", err, "fast", a.localIA,
			"slow", req.Path.SrcIA())
	}
	mac, err := MAC(key, immutableInput)
	if err != nil {
		return false, serrors.WrapStr("validating setup request", err)
	}
	res := subtle.ConstantTimeCompare(mac, req.CurrentValidatorField())
	if res != 1 {
		log.Info("source authentication failed", "id", req.ID,
			"fast_side", a.localIA,
			"slow_side", req.Path.SrcIA(), "mac", hex.EncodeToString(mac),
			"expected", hex.EncodeToString(req.CurrentValidatorField()))
		return false, nil
	}
	return true, nil
}

// validateAtDestination
// payloadFcn takes the index of the path step we want to compute the payload for.
func (a *DrkeyAuthenticator) validateAtDestination(ctx context.Context, req *base.Request,
	payloadFcn func(int) []byte) (bool, error) {

	if len(req.Authenticators) != len(req.Path.Steps)-1 {
		return false, serrors.New("insconsistent length in request",
			"auth_count", len(req.Authenticators), "step_count", len(req.Path.Steps))
	}
	for i := 0; i < len(req.Authenticators)-1; i++ {
		step := req.Path.Steps[i+1]
		payload := payloadFcn(i + 1)
		key, err := a.getDRKeyAS2AS(ctx, step.IA, a.localIA)
		if err != nil {
			return false, serrors.WrapStr("validating source authentic at destination", err)
		}
		mac, err := MAC(key, payload)
		if err != nil {
			return false, serrors.WrapStr("computing mac validating source at destination", err)
		}
		res := subtle.ConstantTimeCompare(mac, req.Authenticators[i])
		if res != 1 {
			log.Info("source authentication failed", "id", req.ID,
				"fast_side", step.IA,
				"slow_side", a.localIA, "mac", hex.EncodeToString(mac),
				"expected", hex.EncodeToString(req.Authenticators[i]))
			return false, nil
		}
	}
	return true, nil
}

func (a *DrkeyAuthenticator) computeInitialMACforPayloadWithSegKeys(ctx context.Context,
	payload []byte, req *base.Request) error {

	keys, err := a.slowAS2ASFromPath(ctx, req.Path)
	if err != nil {
		return err
	}
	return a.computeInitialMACforPayload(ctx, payload, req, keys)
}

func (a *DrkeyAuthenticator) computeInitialMACforPayloadWithE2eKeys(ctx context.Context,
	payload []byte, req *e2e.SetupReq) error {

	keys, err := a.slowAS2HostFromPath(ctx, req)
	if err != nil {
		return err
	}
	return a.computeInitialMACforPayload(ctx, payload, &req.Request, keys)
}

func (a *DrkeyAuthenticator) computeInitialMACforPayload(ctx context.Context, payload []byte,
	req *base.Request, keys [][]byte) error {

	assert(len(keys) == len(req.Path.Steps)-1, "bad key set with length %d (should be %d)",
		len(keys), len(req.Path.Steps)-1)
	var err error
	for i := 0; i < len(req.Path.Steps)-1; i++ {
		req.Authenticators[i], err = MAC(keys[i], payload)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *DrkeyAuthenticator) computeTransitMACforPayload(ctx context.Context, payload []byte,
	req *base.Request) error {

	key, err := a.getDRKeyAS2AS(ctx, a.localIA, req.Path.DstIA())
	if err != nil {
		return err
	}
	req.Authenticators[req.Path.CurrentStep-1], err = MAC(key, payload)
	if err != nil {
		return err
	}
	return nil
}

// slowLvl1FromPath gets the L1 keys from the slow side to all ASes in the path.
func (a *DrkeyAuthenticator) slowAS2ASFromPath(ctx context.Context, path *base.TransparentPath) (
	[][]byte, error) {

	return a.slowKeysFromPath(ctx, path, func(ctx context.Context, fast addr.IA) ([]byte, error) {
		return a.getDRKeyAS2AS(ctx, fast, a.localIA)
	})
}

func (a *DrkeyAuthenticator) slowAS2HostFromPath(ctx context.Context, req *e2e.SetupReq) (
	[][]byte, error) {

	return a.slowKeysFromPath(ctx, req.Path, func(ctx context.Context, fast addr.IA) (
		[]byte, error) {
		// slow side is the initiating host
		return a.getDRKeyAS2Host(ctx, fast, a.localIA, addr.HostFromIP(req.SrcHost))
	})
}

func (a *DrkeyAuthenticator) slowKeysFromPath(ctx context.Context, path *base.TransparentPath,
	getKeyWithFastSide func(ctx context.Context, fast addr.IA) ([]byte, error)) ([][]byte, error) {

	seen := make(map[addr.IA]struct{})
	keys := make([][]byte, len(path.Steps)-1)
	for i := 0; i < len(path.Steps)-1; i++ {
		step := path.Steps[i+1]
		if step.IA.Equal(a.localIA) {
			return nil, serrors.New("request path contains initiator after first step",
				"path", path.String())
		}
		if _, ok := seen[step.IA]; ok {
			return nil, serrors.New("IA is twice in request path", "ia", step.IA, "path", *path)
		}
		seen[step.IA] = struct{}{}
		key, err := getKeyWithFastSide(ctx, step.IA)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	return keys, nil
}

func (a *DrkeyAuthenticator) getDRKeyAS2AS(ctx context.Context, fast, slow addr.IA) (
	[]byte, error) {

	meta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "colibri",
		SrcIA:    fast,
		DstIA:    slow,
	}

	lvl2Key, err := a.connector.DRKeyGetLvl2Key(ctx, meta, time.Now())
	if err != nil {
		return nil, err
	}
	return lvl2Key.Key, nil
}

func (a *DrkeyAuthenticator) getDRKeyAS2Host(ctx context.Context, fast, slowIA addr.IA,
	slowHost addr.HostAddr) ([]byte, error) {

	meta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2Host,
		Protocol: "colibri",
		SrcIA:    fast,
		DstIA:    slowIA,
		DstHost:  slowHost,
	}
	lvl2Key, err := a.connector.DRKeyGetLvl2Key(ctx, meta, time.Now())
	if err != nil {
		return nil, err
	}
	return lvl2Key.Key, nil
}

func inputInitialBaseRequest(buff []byte, req *base.Request) {
	assert(len(buff) >= req.ID.Len()+1+4, "logic error: buffer is too small")
	req.ID.Read(buff)
	buff[req.ID.Len()] = byte(req.Index)
	binary.BigEndian.PutUint32(buff[req.ID.Len()+1:], util.TimeToSecs(req.Timestamp))
}

func inputInitialSegSetupRequest(req *segment.SetupReq) []byte {
	len := req.ID.Len() + 1 + 4 // ID + index + timestamp
	// expTime + RLC + pathType + minBW + maxBW + splitCls + pathProps
	len += 4 + 1 + 1 + 1 + 1 + 1 + 1
	buff := make([]byte, len)

	offset := req.ID.Len() + 1 + 4
	inputInitialBaseRequest(buff[:offset], &req.Request)
	binary.BigEndian.PutUint32(buff[offset:], util.TimeToSecs(req.ExpirationTime))
	offset += 4
	buff[offset] = byte(req.RLC)
	buff[offset+1] = byte(req.PathType)
	buff[offset+2] = byte(req.MinBW)
	buff[offset+3] = byte(req.MaxBW)
	buff[offset+4] = byte(req.SplitCls)
	buff[offset+5] = byte(req.PathProps)
	return buff
}

func inputInitialE2eSetupRequest(req *e2e.SetupReq) []byte {
	length := req.ID.Len() + 1 + 4 // ID + index + timestamp
	// srcIA + srcHost + dstIA + dstHost + BW + seg_reservations
	length += 8 + 16 + 8 + 16 + 1 + len(req.SegmentRsvs)*(reservation.IDSuffixSegLen+6)
	buff := make([]byte, length)

	offset := req.ID.Len() + 1 + 4
	inputInitialBaseRequest(buff[:offset], &req.Request)

	binary.BigEndian.PutUint64(buff[offset:], uint64(req.SrcIA.IAInt()))
	offset += 8
	copy(buff[offset:], req.SrcHost.To16())
	offset += 16
	binary.BigEndian.PutUint64(buff[offset:], uint64(req.DstIA.IAInt()))
	offset += 8
	copy(buff[offset:], req.DstHost.To16())
	offset += 16
	buff[offset] = byte(req.RequestedBW)
	offset++
	for _, id := range req.SegmentRsvs {
		n, _ := id.Read(buff)
		if n != reservation.IDSuffixSegLen+6 {
			panic(fmt.Sprintf("inconsistent id length %d (should be %d)",
				n, reservation.IDSuffixSegLen+6))
		}
		offset += reservation.IDSuffixSegLen + 6
	}

	return buff
}

func inputTransitSegRequest(req *base.Request) []byte {
	// TODO(juagargi) reason about this function: do we need to add something to the initial
	// payload?
	offset := req.ID.Len() + 1 + 4
	buff := make([]byte, offset)
	inputInitialBaseRequest(buff, req)
	return buff
}

func inputTransitSegSetupRequest(req *segment.SetupReq) []byte {
	return inputTransitSegSetupRequestForStep(req, req.Path.CurrentStep)
}

func inputTransitSegSetupRequestForStep(req *segment.SetupReq, step int) []byte {
	initial := inputInitialSegSetupRequest(req)
	bead := req.AllocTrail[step]
	return append(initial, byte(bead.AllocBW), byte(bead.MaxBW))
}

func MAC(key, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
