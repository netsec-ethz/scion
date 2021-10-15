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
	"time"

	"github.com/dchest/cmac"
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
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
}

type macVerifier interface {
	// ValidateRequestInitialMAC verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// this request. Returns true if valid, false otherwise.
	ValidateRequestInitialMAC(ctx context.Context, req *base.Request) (bool, error)
	// ValidateSegmentSetupRequestInitialMAC verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// the setup request. Returns true if valid, false otherwise.
	ValidateSegmentSetupRequestInitialMAC(ctx context.Context, req *segment.SetupReq) (bool, error)
	// ValidateE2eSetupRequestInitialMAC verifies the validity of the source authentication
	// created by the initial AS for this particular transit AS as, for the immutable parts of
	// the setup request. Returns true if valid, false otherwise.
	ValidateE2eSetupRequestInitialMAC(ctx context.Context, req *e2e.SetupReq) (bool, error)
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
	inputInitialSegRequest(payload, req)
	return a.computeInitialMACforPayload(ctx, payload, req)
}

func (a *DrkeyAuthenticator) ComputeSegmentSetupRequestInitialMAC(ctx context.Context,
	req *segment.SetupReq) error {

	payload := inputInitialSegSetupRequest(req)
	return a.computeInitialMACforPayload(ctx, payload, &req.Request)
}

func (a *DrkeyAuthenticator) ValidateRequestInitialMAC(ctx context.Context,
	req *base.Request) (bool, error) {

	immutableInput := make([]byte, req.ID.Len()+1+4)
	inputInitialSegRequest(immutableInput, req)
	return a.validateSegmentPayloadInitialMAC(ctx, req, immutableInput)
}

func (a *DrkeyAuthenticator) ValidateSegmentSetupRequestInitialMAC(ctx context.Context,
	req *segment.SetupReq) (bool, error) {

	return a.validateSegmentPayloadInitialMAC(ctx, &req.Request, inputInitialSegSetupRequest(req))

}

func (a *DrkeyAuthenticator) ValidateE2eSetupRequestInitialMAC(ctx context.Context,
	req *e2e.SetupReq) (bool, error) {

	// TODO(juagargi) deleteme: implement
	return false, nil

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

func (a *DrkeyAuthenticator) computeInitialMACforPayload(ctx context.Context, payload []byte,
	req *base.Request) error {

	keys, err := a.slowAS2ASFromPath(ctx, req.Path)
	if err != nil {
		return err
	}
	assert(len(keys) == len(req.Path.Steps)-1, "bad key set with length %d (should be %d)",
		len(keys), len(req.Path.Steps)-1)
	for i := 1; i < len(req.Path.Steps); i++ {
		step := req.Path.Steps[i]
		key := keys[step.IA]

		req.Authenticators[i-1], err = MAC(key, payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// slowLvl1FromPath gets the L1 keys from the slow side to all ASes in the path.
func (a *DrkeyAuthenticator) slowAS2ASFromPath(ctx context.Context, path *base.TransparentPath) (
	map[addr.IA][]byte, error) {

	keys := make(map[addr.IA][]byte)
	for _, step := range path.Steps {
		if step.IA.Equal(a.localIA) {
			continue // skip the reservation initiator
		}
		key, err := a.getDRKeyAS2AS(ctx, step.IA, a.localIA)
		if err != nil {
			return nil, err
		}
		keys[step.IA] = key
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

func inputInitialSegRequest(buff []byte, req *base.Request) {
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
	inputInitialSegRequest(buff[:offset], &req.Request)
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
