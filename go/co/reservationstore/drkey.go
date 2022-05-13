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

package reservationstore

import (
	"context"
	"crypto/aes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dchest/cmac"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	drkeyctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Authenticator interface {
	macComputer
	macVerifier
}

type macComputer interface {
	// ComputeRequestInitialMAC computes the MAC for the immutable fields of the basic request,
	// for each AS in transit. This MAC is only computed at the first AS.
	// The initial AS is obtained from the first step of the path of the request.
	ComputeRequestInitialMAC(ctx context.Context, req *base.Request, steps base.PathSteps) error
	// SegmentRequestInitialMAC computes the MAC for the immutable fields of the setup request,
	// for each AS in transit. This MAC is only computed at the first AS.
	// The initial AS is obtained from the first step of the path of the request.
	ComputeSegmentSetupRequestInitialMAC(ctx context.Context, req *segment.SetupReq, steps base.PathSteps) error
	ComputeRequestTransitMAC(ctx context.Context, req *base.Request, dstIA addr.IA,
		currentStep int, steps base.PathSteps) error

	ComputeSegmentSetupRequestTransitMAC(ctx context.Context, req *segment.SetupReq, dstIA addr.IA, currentStep int) error
	ComputeE2ERequestTransitMAC(ctx context.Context, req *e2e.Request, dstIA addr.IA, currentStep int) error
	ComputeE2ESetupRequestTransitMAC(ctx context.Context, req *e2e.SetupReq, dstIA addr.IA, currentStep int) error

	// ComputeResponseMAC takes the response (passed as an interface here) and computes and sets
	// the authenticators inside it.
	// These authenticators will be later validated at the source end-host.
	ComputeResponseMAC(ctx context.Context,
		res base.Response, srcIA addr.IA, currentStep int) error
	ComputeSegmentSetupResponseMAC(ctx context.Context,
		res segment.SegmentSetupResponse, steps base.PathSteps, currentStep int) error
	ComputeE2EResponseMAC(ctx context.Context, res base.Response,
		currentStep int, srcIA addr.IA, srcHost addr.HostAddr) error
	ComputeE2ESetupResponseMAC(ctx context.Context, res e2e.SetupResponse,
		pcurrentStep int, srcIA addr.IA, srcHost addr.HostAddr, rsvID *reservation.ID) error
}

type macVerifier interface {
	// ValidateRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateRequest(ctx context.Context, remote addr.IA,
		req *base.Request, currentStep int, steps base.PathSteps) (bool, error)
	// ValidateSegSetupRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateSegSetupRequest(ctx context.Context, req *segment.SetupReq, currentStep int) (bool, error)
	// Validates a basic E2E request while in a transit AS.
	// The authenticators were created on the source host.
	ValidateE2ERequest(ctx context.Context, req *e2e.Request) (bool, error)
	// ValidateE2ESetupRequest verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. If the request is now at the last AS, it also validates the request at
	// the destination. Returns true if valid, false otherwise.
	ValidateE2ESetupRequest(ctx context.Context, req *e2e.SetupReq) (bool, error)

	ValidateResponse(ctx context.Context, res base.Response,
		steps base.PathSteps) (bool, error)
	ValidateSegmentSetupResponse(ctx context.Context,
		res segment.SegmentSetupResponse, steps []base.PathStep) (bool, error)
}

// DRKeyAuthenticator implements macComputer and macVerifier using DRKey.
type DRKeyAuthenticator struct {
	localIA   addr.IA
	fastKeyer fastKeyer
	slowKeyer slowKeyer
}

func NewDRKeyAuthenticator(localIA addr.IA, dialer libgrpc.Dialer) Authenticator {
	return &DRKeyAuthenticator{
		localIA: localIA,
		fastKeyer: &deriver{
			localIA: localIA,
			secreter: &cachingSVfetcher{
				dialer: dialer,
			},
		},
		slowKeyer: newLvl1Fetcher(localIA, dialer),
	}
}

func (a *DRKeyAuthenticator) ComputeRequestInitialMAC(ctx context.Context,
	req *base.Request, steps base.PathSteps) error {

	payload := inputInitialBaseRequest(req)
	return a.computeInitialMACforPayloadWithSegKeys(ctx, payload, req, steps)
}

func (a *DRKeyAuthenticator) ComputeSegmentSetupRequestInitialMAC(ctx context.Context,
	req *segment.SetupReq, steps base.PathSteps) error {

	payload := inputInitialSegSetupRequest(req)
	return a.computeInitialMACforPayloadWithSegKeys(ctx, payload, &req.Request, steps)
}

func (a *DRKeyAuthenticator) ComputeRequestTransitMAC(ctx context.Context,
	req *base.Request, dstIA addr.IA, currentStep int, steps base.PathSteps) error {

	if currentStep == 0 || currentStep >= len(steps)-1 {
		return nil
	}
	payload := inputTransitSegRequest(req)
	return a.computeTransitMACforPayload(ctx, payload, req, dstIA, currentStep)
}

func (a *DRKeyAuthenticator) ComputeSegmentSetupRequestTransitMAC(ctx context.Context,
	req *segment.SetupReq, dstIA addr.IA, currentStep int) error {

	if currentStep == 0 || currentStep >= len(req.Steps)-1 {
		return nil
	}
	payload := inputTransitSegSetupRequest(req)
	return a.computeTransitMACforPayload(ctx, payload, &req.Request, dstIA, currentStep)
}

func (a *DRKeyAuthenticator) ComputeE2ERequestTransitMAC(ctx context.Context,
	req *e2e.Request, dstIA addr.IA, currentStep int) error {

	if req.IsFirstAS() || req.IsLastAS() {
		return nil
	}
	payload := inputTransitE2ERequest(req)
	return a.computeTransitMACforE2EPayload(ctx, payload, req, dstIA, currentStep)
}

func (a *DRKeyAuthenticator) ComputeE2ESetupRequestTransitMAC(ctx context.Context,
	req *e2e.SetupReq, dstIA addr.IA, currentStep int) error {

	if req.IsFirstAS() || req.IsLastAS() {
		return nil
	}
	payload := inputTransitE2ESetupRequest(req)
	return a.computeTransitMACforE2EPayload(ctx, payload, &req.Request, dstIA, currentStep)
}

func (a *DRKeyAuthenticator) ComputeResponseMAC(ctx context.Context,
	res base.Response, srcIA addr.IA, currentStep int) error {

	key, err := a.fastAS2AS(ctx, srcIA, res.GetTimestamp())
	if err != nil {
		return err
	}
	payload := res.ToRaw()
	mac, err := MAC(payload, key.Key)
	if err != nil {
		return err
	}
	res.SetAuthenticator(currentStep, mac)
	return nil
}

func (a *DRKeyAuthenticator) ComputeSegmentSetupResponseMAC(ctx context.Context,
	res segment.SegmentSetupResponse, steps base.PathSteps, currentStep int) error {

	key, err := a.fastAS2AS(ctx, steps.SrcIA(), res.GetTimestamp())
	if err != nil {
		return err
	}
	payload := res.ToRawAllHFs()
	mac, err := MAC(payload, key.Key)
	if err != nil {
		return err
	}
	res.SetAuthenticator(currentStep, mac)
	return nil
}

func (a *DRKeyAuthenticator) ComputeE2EResponseMAC(ctx context.Context, res base.Response,
	currentStep int, srcIA addr.IA, srcHost addr.HostAddr) error {

	key, err := a.fastAS2Host(ctx, srcIA, srcHost, res.GetTimestamp())
	if err != nil {
		return err
	}
	payload := res.ToRaw()
	mac, err := MAC(payload, key.Key)
	if err != nil {
		return err
	}
	// because base.Response.SetAuthenticator will use step-1 for the auth position, but we
	// actually want the [step] position, add one:
	res.SetAuthenticator(currentStep+1, mac)
	return nil
}

func (a *DRKeyAuthenticator) ComputeE2ESetupResponseMAC(ctx context.Context, res e2e.SetupResponse,
	currentStep int, srcIA addr.IA, srcHost addr.HostAddr, rsvID *reservation.ID) error {

	key, err := a.fastAS2Host(ctx, srcIA, srcHost, res.GetTimestamp())
	if err != nil {
		return err
	}
	payload, err := res.ToRaw(currentStep, rsvID)
	if err != nil {
		return err
	}
	mac, err := MAC(payload, key.Key)
	if err != nil {
		return err
	}
	res.SetAuthenticator(currentStep, mac)
	return nil
}

func (a *DRKeyAuthenticator) ValidateRequest(ctx context.Context, remote addr.IA,
	req *base.Request, currentStep int, steps base.PathSteps) (bool, error) {

	ok, err := a.validateSegmentPayloadInitialMAC(ctx, req.ID, remote,
		req.Authenticators[currentStep-1], req.Timestamp, inputInitialBaseRequest(req))
	if err == nil && ok && currentStep >= len(steps)-1 {
		ok, err = a.validateRequestAtDestination(ctx, req, steps)
	}
	return ok, err
}

func (a *DRKeyAuthenticator) ValidateSegSetupRequest(ctx context.Context,
	req *segment.SetupReq, currentStep int) (bool, error) {

	if currentStep == 0 {
		return true, nil
	}
	ok, err := a.validateSegmentPayloadInitialMAC(ctx, req.ID, req.Steps.SrcIA(),
		req.Authenticators[currentStep-1], req.Timestamp,
		inputInitialSegSetupRequest(req))
	if err == nil && ok && currentStep >= len(req.Steps)-1 {
		ok, err = a.validateSegmentSetupRequestAtDestination(ctx, req, req.Steps)
	}
	return ok, err
}

func (a *DRKeyAuthenticator) ValidateE2ERequest(ctx context.Context, req *e2e.Request) (
	bool, error) {

	if req.IsFirstAS() {
		return true, nil
	}
	payload := make([]byte, req.Len())
	req.Serialize(payload, base.SerializeImmutable)

	ok, err := a.validateE2EPayloadInitialMAC(ctx, req, payload)
	if err == nil && ok && req.IsLastAS() {
		ok, err = a.validateE2ERequestAtDestination(ctx, req, req.Steps)
	}

	return ok, err
}

func (a *DRKeyAuthenticator) ValidateE2ESetupRequest(ctx context.Context,
	req *e2e.SetupReq) (bool, error) {

	if req.IsFirstAS() {
		return true, nil
	}
	payload := make([]byte, req.Len())
	req.Serialize(payload, base.SerializeImmutable)

	ok, err := a.validateE2EPayloadInitialMAC(ctx, &req.Request, payload)
	if err == nil && ok && req.IsLastAS() {
		ok, err = a.validateE2ESetupRequestAtDestination(ctx, req, req.Steps)
	}
	return ok, err

}

func (a *DRKeyAuthenticator) ValidateResponse(ctx context.Context, res base.Response,
	steps base.PathSteps) (bool, error) {

	keys, err := a.slowAS2ASFromPath(ctx, steps, res.GetTimestamp())
	if err != nil {
		return false, err
	}
	payload := res.ToRaw()
	return validateAuthenticators(keys, res.GetAuthenticators(), func(int) []byte {
		return payload
	})
}

func (a *DRKeyAuthenticator) ValidateSegmentSetupResponse(ctx context.Context,
	res segment.SegmentSetupResponse, steps []base.PathStep) (bool, error) {

	stepsLength := len(steps)
	if failure, ok := res.(*segment.SegmentSetupResponseFailure); ok {
		// for failure responses, we can only check the validity from the failing node to
		// the initiator node, as the ones that succeed were using a different response to
		// compute the authenticators.
		stepsLength = int(failure.FailedStep)
	} else if success, ok := res.(*segment.SegmentSetupResponseSuccess); ok {
		assert(len(success.Token.HopFields) == len(steps),
			"inconsistent lengths HFs=%d and steps=%d", len(success.Token.HopFields),
			len(steps))
	}
	if stepsLength == 0 {
		log.Debug("at validateSegmentSetupResponse: no steps to validate (steps_length==0)")
		return true, nil
	}

	keys, err := a.slowAS2ASFromPath(ctx, steps[:stepsLength],
		res.GetTimestamp()) // returns stepsLength -1 keys
	if err != nil {
		return false, err
	}

	return validateAuthenticators(keys, res.GetAuthenticators()[:stepsLength-1],
		func(step int) []byte {
			return res.ToRaw(step)
		})
}

func (a *DRKeyAuthenticator) validateRequestAtDestination(ctx context.Context,
	req *base.Request, steps []base.PathStep) (
	bool, error) {

	return a.validateAtDestination(ctx, req, steps, func(i int) []byte {
		return inputTransitSegRequest(req)
	})
}

func (a *DRKeyAuthenticator) validateSegmentSetupRequestAtDestination(ctx context.Context,
	req *segment.SetupReq, steps []base.PathStep) (bool, error) {

	return a.validateAtDestination(ctx, &req.Request, steps, func(step int) []byte {
		return inputTransitSegSetupRequestForStep(req, step)
	})
}

func (a *DRKeyAuthenticator) validateE2ERequestAtDestination(ctx context.Context,
	req *e2e.Request, steps []base.PathStep) (bool, error) {

	return a.validateAtDestination(ctx, &req.Request, steps, func(step int) []byte {
		return inputTransitE2ERequest(req)
	})
}

func (a *DRKeyAuthenticator) validateE2ESetupRequestAtDestination(ctx context.Context,
	req *e2e.SetupReq, steps []base.PathStep) (bool, error) {

	return a.validateAtDestination(ctx, &req.Request.Request, steps, func(step int) []byte {
		return inputTransitE2ESetupRequestForStep(req, step)
	})
}

func (a *DRKeyAuthenticator) validateSegmentPayloadInitialMAC(ctx context.Context, reqID reservation.ID,
	srcIA addr.IA, currValidator []byte, ts time.Time, immutableInput []byte) (bool, error) {

	key, err := a.fastAS2AS(ctx, srcIA, ts)
	if err != nil {
		return false, serrors.WrapStr("obtaining drkey", err, "fast", a.localIA,
			"slow", srcIA)
	}
	mac, err := MAC(immutableInput, key.Key)
	if err != nil {
		return false, serrors.WrapStr("validating segment initial request", err)
	}
	res := subtle.ConstantTimeCompare(mac, currValidator)
	if res != 1 {
		log.FromCtx(ctx).Info("source authentication failed", "id", reqID,
			"fast_side", a.localIA,
			"slow_side", srcIA, "mac", hex.EncodeToString(mac),
			"expected", hex.EncodeToString(currValidator))
		return false, nil
	}
	return true, nil
}

// validateE2EPayloadInitialMAC obtains the (fast side this) key according to req.Path and
// uses them to compute the MAC from payload and compare it with the current req.Authenticators.
func (a *DRKeyAuthenticator) validateE2EPayloadInitialMAC(ctx context.Context,
	req *e2e.Request, immutableInput []byte) (bool, error) {

	key, err := a.fastAS2Host(ctx, req.Steps.SrcIA(), addr.HostFromIP(req.SrcHost), req.Timestamp)
	if err != nil {
		return false, serrors.WrapStr("obtaining drkey", err, "fast", a.localIA,
			"slow_ia", req.Steps.SrcIA(), "slow_host", req.SrcHost)
	}
	mac, err := MAC(immutableInput, key.Key)
	if err != nil {
		return false, serrors.WrapStr("validating e2e initial request", err)
	}
	res := subtle.ConstantTimeCompare(mac, req.CurrentValidatorField())
	if res != 1 {
		log.FromCtx(ctx).Info("source authentication failed", "id", req.ID,
			"fast_side", a.localIA,
			"slow_ia", req.Steps.SrcIA(), "slow_host", req.SrcHost,
			"mac", hex.EncodeToString(mac),
			"expected", hex.EncodeToString(req.CurrentValidatorField()))
		return false, nil
	}
	return true, nil
}

// validateAtDestination validates the authenticators created in-transit. The first
// authenticator, authenticators[0], is created by the second in-path AS. The last
// authenticator, authenticator[n-1], should have been created by the destination AS,
// but since there is no need to authenticate it to itself, it's left empty.
// payloadFcn takes the index of the path step we want to compute the payload for.
func (a *DRKeyAuthenticator) validateAtDestination(ctx context.Context, req *base.Request,
	steps base.PathSteps,
	payloadFcn func(int) []byte) (bool, error) {

	if len(req.Authenticators) != len(steps)-1 {
		return false, serrors.New("insconsistent length in request",
			"auth_count", len(req.Authenticators), "step_count", len(steps))
	}
	keys, err := a.slowAS2ASFromPath(ctx, steps[:len(steps)-1], req.Timestamp)
	if err != nil {
		return false, serrors.WrapStr("source authentication failed", err, "id", req.ID)
	}
	// we have 1 less key than authenticators (we don't want to validate the last authenticator,
	// as it is the place of the destination AS, which is this one)
	return validateAuthenticators(keys, req.Authenticators[:len(req.Authenticators)-1],
		payloadFcn)
}

func validateAuthenticators(keys []drkey.Key, authenticators [][]byte,
	payloadFcn func(step int) []byte) (bool, error) {

	if len(authenticators) != len(keys) {
		return false, serrors.New("insconsistent length",
			"auth_count", len(authenticators), "key_count", len(keys))
	}
	for i := 0; i < len(authenticators); i++ {
		payload := payloadFcn(i + 1)
		mac, err := MAC(payload, keys[i])
		if err != nil {
			return false, serrors.WrapStr("computing mac validating source at destination", err)
		}
		res := subtle.ConstantTimeCompare(mac, authenticators[i])
		if res != 1 {
			log.Info("source authentication failed",
				"step", i,
				"mac", hex.EncodeToString(mac),
				"expected", hex.EncodeToString(authenticators[i]))
			return false, nil
		}
	}
	return true, nil
}

func (a *DRKeyAuthenticator) computeInitialMACforPayloadWithSegKeys(ctx context.Context,
	payload []byte, req *base.Request, steps base.PathSteps) error {

	keys, err := a.slowAS2ASFromPath(ctx, steps, req.Timestamp)
	if err != nil {
		return err
	}
	return a.computeInitialMACforPayload(ctx, payload, req, keys)
}

func (a *DRKeyAuthenticator) computeInitialMACforPayload(ctx context.Context, payload []byte,
	req *base.Request, keys []drkey.Key) error {

	assert(len(keys) == len(req.Authenticators), "bad key set with length %d (should be %d)",
		len(keys), len(req.Authenticators))
	var err error
	for i := 0; i < len(keys); i++ {
		req.Authenticators[i], err = MAC(payload, keys[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *DRKeyAuthenticator) computeTransitMACforPayload(ctx context.Context, payload []byte,
	req *base.Request, dstIA addr.IA, currentStep int) error {

	key, err := a.fastAS2AS(ctx, dstIA, req.Timestamp)
	if err != nil {
		return err
	}
	req.Authenticators[currentStep-1], err = MAC(payload, key.Key)
	return err
}

func (a *DRKeyAuthenticator) computeTransitMACforE2EPayload(ctx context.Context, payload []byte,
	req *e2e.Request, dstIA addr.IA, currentStep int) error {

	key, err := a.fastAS2AS(ctx, dstIA, req.Timestamp)
	if err != nil {
		return err
	}
	req.Authenticators[currentStep-1], err = MAC(payload, key.Key)
	return err
}

// slowAS2ASFromPath gets the AS-AS keys from the slow side to all ASes in the path.
// Note: this is the slow side.
func (a *DRKeyAuthenticator) slowAS2ASFromPath(ctx context.Context,
	steps base.PathSteps, ts time.Time) (
	[]drkey.Key, error) {

	return a.slowKeysFromPath(ctx, steps, func(ctx context.Context,
		fast addr.IA) (drkey.Key, error) {
		k, err := a.slowAS2AS(ctx, fast, ts)
		return k.Key, err
	})
}

// slowKeysFromPath retrieves the drkeys specified in the steps[1]..steps[n-1]. It skips the
// first step as it is the initiator. The IAs in the steps are used as the fast side of the
// drkeys, and the function `getKeyWithFastSide` is called with them, to retrieve the drkeys.
func (a *DRKeyAuthenticator) slowKeysFromPath(ctx context.Context,
	steps base.PathSteps,
	getKeyWithFastSide func(ctx context.Context,
		fast addr.IA) (drkey.Key, error)) ([]drkey.Key, error) {

	seen := make(map[addr.IA]struct{})
	keys := make([]drkey.Key, len(steps)-1)
	for i := 0; i < len(steps)-1; i++ {
		step := steps[i+1]
		if step.IA.Equal(a.localIA) {
			return nil, serrors.New("request path contains initiator after first step",
				"steps", base.StepsToString(steps))
		}
		if _, ok := seen[step.IA]; ok {
			return nil, serrors.New("IA is twice in request path", "ia", step.IA,
				"steps", base.StepsToString(steps))
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

func (a *DRKeyAuthenticator) fastAS2AS(ctx context.Context, remoteIA addr.IA,
	valTime time.Time) (drkey.Lvl1Key, error) {
	return a.fastKeyer.Lvl1(ctx, drkey.Lvl1Meta{
		ProtoId:  drkey.COLIBRI,
		Validity: valTime,
		SrcIA:    a.localIA,
		DstIA:    remoteIA,
	})
}

func (a *DRKeyAuthenticator) slowAS2AS(ctx context.Context, remoteIA addr.IA,
	valTime time.Time) (drkey.Lvl1Key, error) {
	return a.slowKeyer.Lvl1(ctx, drkey.Lvl1Meta{
		ProtoId:  drkey.COLIBRI,
		Validity: valTime,
		SrcIA:    remoteIA,
		DstIA:    a.localIA,
	})
}

func (a *DRKeyAuthenticator) fastAS2Host(ctx context.Context, remoteIA addr.IA,
	remoteHost addr.HostAddr, valTime time.Time) (drkey.ASHostKey, error) {

	return a.fastKeyer.ASHost(ctx, drkey.ASHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.COLIBRI,
			Validity: valTime,
			SrcIA:    a.localIA,
			DstIA:    remoteIA,
		},
		DstHost: remoteHost.String(),
	})
}

func inputInitialBaseRequest(req *base.Request) []byte {
	buff := make([]byte, req.Len())
	req.Serialize(buff, base.SerializeImmutable)
	return buff
}

func inputInitialSegSetupRequest(req *segment.SetupReq) []byte {
	buff := make([]byte, req.Len())
	req.Serialize(buff, base.SerializeImmutable)
	return buff
}

func inputTransitSegRequest(req *base.Request) []byte {
	buff := make([]byte, req.Len())
	req.Serialize(buff, base.SerializeImmutable)
	return buff
}

func inputTransitSegSetupRequest(req *segment.SetupReq) []byte {
	buff := make([]byte, req.Len()+len(req.AllocTrail)*2)
	req.Serialize(buff, base.SerializeSemiMutable)
	return buff
}

// inputTransitSegSetupRequestForStep is used by the validation of the segment setup request at
// destination. The validation function needs to get the semi mutable payload per AS in the trail,
// thus different ASes will yield different payloads.
func inputTransitSegSetupRequestForStep(req *segment.SetupReq, step int) []byte {
	buff := inputTransitSegSetupRequest(req)
	remainingSteps := len(req.AllocTrail) - step - 1
	return buff[:len(buff)-remainingSteps*2]
}

func inputTransitE2ERequest(req *e2e.Request) []byte {
	buff := make([]byte, req.Len())
	req.Serialize(buff, base.SerializeSemiMutable)
	return buff
}

func inputTransitE2ESetupRequest(req *e2e.SetupReq) []byte {
	buff := make([]byte, req.Len()+len(req.AllocationTrail))
	req.Serialize(buff, base.SerializeSemiMutable)
	return buff
}

// inputTransitE2ESetupRequestForStep serializes the semi mutable fields of req as if it
// were located at step `step`.
func inputTransitE2ESetupRequestForStep(req *e2e.SetupReq, step int) []byte {
	buff := inputTransitE2ESetupRequest(req)
	remainingSteps := len(req.AllocationTrail) - step - 1
	return buff[:len(buff)-remainingSteps]
}

func MAC(payload []byte, key drkey.Key) ([]byte, error) {
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

type fastKeyer interface {
	Lvl1(context.Context, drkey.Lvl1Meta) (drkey.Lvl1Key, error)
	ASHost(context.Context, drkey.ASHostMeta) (drkey.ASHostKey, error)
}

type deriver struct {
	localIA  addr.IA
	secreter secreter
	deriver  drkey.SpecificDeriver
}

func (d *deriver) Lvl1(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	if meta.SrcIA != d.localIA {
		panic(fmt.Sprintf("cannot derive, SrcIA != localIA, SrcIA=%s, localIA=%s",
			meta.SrcIA, d.localIA))
	}

	svMeta := drkey.SVMeta{
		Validity: meta.Validity,
		ProtoId:  meta.ProtoId,
	}
	sv, err := d.secreter.SV(ctx, svMeta)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	lvl1, err := d.deriver.DeriveLvl1(meta, sv.Key)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	return drkey.Lvl1Key{
		ProtoId: meta.ProtoId,
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Key:     lvl1,
	}, nil
}

func (d *deriver) ASHost(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	lvl1Meta := drkey.Lvl1Meta{
		Validity: meta.Validity,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		ProtoId:  meta.ProtoId,
	}
	lvl1, err := d.Lvl1(ctx, lvl1Meta)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	lvl2, err := d.deriver.DeriveASHost(meta, lvl1.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		DstHost: meta.DstHost,
		Key:     lvl2,
	}, nil
}

type slowKeyer interface {
	Lvl1(context.Context, drkey.Lvl1Meta) (drkey.Lvl1Key, error)
}

type lvl1Fetcher struct {
	mtx     sync.Mutex
	localIA addr.IA
	dialer  libgrpc.Dialer
	cache   map[addr.IA][]drkey.Lvl1Key // TODO expired entries should be cleaned up periodically
}

func newLvl1Fetcher(localIA addr.IA, dialer libgrpc.Dialer) *lvl1Fetcher {
	return &lvl1Fetcher{
		localIA: localIA,
		dialer:  dialer,
		cache:   map[addr.IA][]drkey.Lvl1Key{},
	}
}

func (f *lvl1Fetcher) Lvl1(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if meta.ProtoId != drkey.COLIBRI {
		return drkey.Lvl1Key{}, serrors.New("meta.ProtoId must be set to COLIBRI",
			"meta.ProtoId", meta.ProtoId)
	}

	if meta.DstIA != f.localIA {
		return drkey.Lvl1Key{}, serrors.New("cannot fetch, DstIA != localIA", "DstIA=", f.localIA,
			"localIA=", meta.DstIA)
	}

	lvl1Keys, ok := f.cache[meta.SrcIA]
	if ok {
		for _, key := range lvl1Keys {
			if key.Epoch.Contains(meta.Validity) {
				return key, nil
			}
		}
	}

	// get it from local CS
	lvl1Key, err := f.fetch(ctx, meta)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from CS", err)
	}
	f.cache[meta.SrcIA] = append(f.cache[meta.SrcIA], lvl1Key)

	return lvl1Key, nil
}

func (f *lvl1Fetcher) fetch(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	conn, err := f.dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.IntraLvl1ToProtoRequest(meta)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing AS-AS request to protobuf", err)
	}
	rep, err := client.IntraLvl1(ctx, protoReq)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("requesting AS-AS key", err)
	}
	key, err := drkeyctrl.GetASASKeyFromReply(meta, rep)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining AS-AS key from reply", err)
	}
	return key, nil
}

type secreter interface {
	SV(context.Context, drkey.SVMeta) (drkey.SV, error)
}

type cachingSVfetcher struct {
	dialer libgrpc.Dialer
	cache  []drkey.SV // TODO expired entries should be cleaned up periodically
	mtx    sync.Mutex // TODO could use RWMutex, but should be careful to avoid double-fetching SV!
}

func (f *cachingSVfetcher) SV(ctx context.Context, meta drkey.SVMeta) (drkey.SV, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if meta.ProtoId != drkey.COLIBRI {
		return drkey.SV{}, serrors.New("meta.ProtoId must be set to COLIBRI",
			"meta.ProtoId", meta.ProtoId)
	}

	for i := range f.cache {
		if f.cache[i].Epoch.Contains(meta.Validity) {
			return f.cache[i], nil
		}
	}

	key, err := f.fetch(ctx, meta)
	if err != nil {
		return drkey.SV{}, err
	}
	f.cache = append(f.cache, key)
	return key, nil
}

func (f *cachingSVfetcher) fetch(ctx context.Context, meta drkey.SVMeta) (drkey.SV, error) {
	conn, err := f.dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.SVMetaToProtoRequest(meta)
	if err != nil {
		return drkey.SV{},
			serrors.WrapStr("parsing SV request to protobuf", err)
	}
	rep, err := client.SV(ctx, protoReq)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("requesting SV", err)
	}
	key, err := drkeyctrl.GetSVFromReply(meta.ProtoId, rep)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("obtaining SV from reply", err)
	}
	return key, nil
}
