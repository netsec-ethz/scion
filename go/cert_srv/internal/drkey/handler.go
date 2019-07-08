// Copyright 2019 ETH Zurich
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

package drkey

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	AddressMismatchError = "Source IA of packet did not match IA in DRKey"
)

const (
	DRKeyHandlerTimeout = 5 * time.Second
)

// Level1ReqHandler handles first-level drkey requests.
type Level1ReqHandler struct {
	State *config.State
	IA    addr.IA
}

// Handle handles the level 1 drkey requests
func (h *Level1ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	srcIA := saddr.IA
	dstIA := req.DstIa.IA()
	log.Debug("[DRKeyLevel1ReqHandler] Received request", "srcIA", srcIA, "dstIA", dstIA)

	sv := getSecretValue()
	// Get the newest certificate for the remote AS
	dstChain, err := h.State.TrustDB.GetChainMaxVersion(ctx, req.DstIA())
	if err != nil {
		log.Error("[DRKeyLevel1ReqHandler] Unable to fetch certificate for remote AS", "err", err)
		return infra.MetricsErrInternal
	}
	privateKey := h.State.GetDecryptKey()
	reply, err := Level1KeyBuildReply(srcIA, dstIA, sv, dstChain.Leaf, privateKey)
	if err != nil {
		log.Error("[DRKeyLevel1ReqHandler]", "err", err)
		return infra.MetricsErrInternal
	}

	if err := h.sendRep(ctx, saddr, reply, r.ID); err != nil {
		log.Error("[DRKeyLevel1ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// Level1KeyBuildReply constructs the level 1 key exchange reply message
// cipher = {A | B | K_{A->B}}_PK_B
// nonce = nonce
// Epoch comes from the secret value (configuration)
func Level1KeyBuildReply(srcIA, dstIA addr.IA, sv *drkey.DRKeySV, cert *cert.Certificate, privateKey common.RawBytes) (reply *drkey_mgmt.DRKeyLvl1Rep, err error) {
	if err = validateReq(srcIA, dstIA); err != nil {
		err = common.NewBasicError("Dropping DRKeyLvl1 request, validation error", err)
		return
	}

	key, err := deriveLvl1Key(srcIA, dstIA, sv)
	if err != nil {
		err = common.NewBasicError("Unable to derive drkey", err)
		return
	}

	nonce, err := scrypto.Nonce(24)
	if err != nil {
		err = common.NewBasicError("Unable to get random nonce drkey", err)
		return
	}
	cipher, err := drkey.EncryptDRKeyLvl1(key, nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		err = common.NewBasicError("Unable to encrypt drkey", err)
		return
	}

	// XXX(juan) originally SrcIa was     h.IA.IAInt(),
	reply = &drkey_mgmt.DRKeyLvl1Rep{
		SrcIa:      srcIA.IAInt(),
		EpochBegin: sv.Epoch.Begin,
		EpochEnd:   sv.Epoch.End,
		Cipher:     cipher,
		Nonce:      nonce,
		CertVerDst: cert.Version,
	}
	return
}

func getSecretValue() *drkey.DRKeySV {
	// TODO: drkeytest: add the SV to the configuration
	return &drkey.DRKeySV{}
}

func validateReq(srcIA, dstIA addr.IA) error {
	// TODO(ben): validate request (validity time, etc.)
	// TODO(ben): remove
	log.Debug("[DRKeyReqHandler] Validating drkey lvl1 request", "src", srcIA, "dst", dstIA)
	// if !srcIA.Eq(req.SrcIa.IA()) {
	// 	return common.NewBasicError(AddressMismatchError, nil,
	// 		"expected", addr.IA, "actual", req.SrcIa.IA())
	// }
	return nil
}

func deriveLvl1Key(srcIA, dstIA addr.IA, sv *drkey.DRKeySV) (*drkey.DRKeyLvl1, error) {
	// TODO(ben): remove
	log.Debug("[DRKeyReqHandler] Deriving drkey for lvl1 request", "srcIA", srcIA, "dstIA", dstIA)
	key := &drkey.DRKeyLvl1{
		DRKey: drkey.DRKey{Epoch: sv.Epoch},
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	if err := key.SetKey(sv.Key); err != nil {
		return nil, err
	}
	return key, nil
}

func (h *Level1ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl1Rep, id uint64) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError(
			"[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl1(ctx, rep)
}

// Level1ReplyHandler handles first-level drkey replies.
type Level1ReplyHandler struct {
	State *config.State
}

// Handle handles the a level drkey reply
func (h *Level1ReplyHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()

	saddr := r.Peer.(*snet.Addr)
	reply := r.Message.(*drkey_mgmt.DRKeyLvl1Rep)
	log.Debug("[Level1ReplyHandler] Received drkey lvl1 reply", "addr", saddr, "reply", reply)
	if reply == nil {
		log.Error("[Level1ReplyHandler] Reply is null after cast")
		return infra.MetricsErrInternal
	}
	// cert, err := h.State.TrustDB.GetLeafCertMaxVersion(ctx, reply.IA())
	chain, err := h.State.TrustDB.GetChainMaxVersion(ctx, reply.IA())
	if err != nil {
		log.Error("[Level1ReplyHandler] Unable to fetch certificate for remote host", "err", err)
		return infra.MetricsErrInternal
	}
	privateKey := h.State.GetDecryptKey()

	key, err := Level1KeyFromReply(reply, saddr.IA, chain.Leaf, privateKey)
	_, err = h.State.DRKeyStore.InsertDRKeyLvl1Ctx(ctx, key)
	if err != nil {
		log.Error("[Level1ReplyHandler] Could not insert the DR key in the DB", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// Level1KeyFromReply validates a level 1 reply and returns the level 1 key embedded in it
func Level1KeyFromReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA, cert *cert.Certificate, privateKey common.RawBytes) (key *drkey.DRKeyLvl1, err error) {
	if err = validateReply(reply, srcIA); err != nil {
		err = common.NewBasicError("Dropping DRKeyLvl1 reply", err)
		return
	}
	// TODO(juan): match this reply with a request from this CS
	key, err = drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		err = common.NewBasicError("Error decrypting the key from the reply", err)
		return
	}
	log.Debug("[Level1ReplyHandler] DRKey received", "key", key)
	key.Epoch = reply.Epoch()

	return
}

func validateReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA) error {
	// TODO(ben): validate reply (validity time, etc.)
	log.Debug("[Level1ReplyHandler] Validating drkey lvl1 reply", "reply", reply)
	if !srcIA.Equal(reply.SrcIa.IA()) {
		return common.NewBasicError(AddressMismatchError, nil, "expected", srcIA, "actual", reply.SrcIa.IA())
	}
	return nil
}

type Level2ReqHandler struct {
	State *config.State
	IA    addr.IA
}

// Handle handles the level 1 drkey requests
func (h *Level2ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl2Req)
	log.Debug("[DRKeyLevel2ReqHandler] Received request", "req", req)

	srcIA := saddr.IA
	dstIA := req.DstIA()
	srcHost := req.SrcHost.ToHostAddr()
	dstHost := req.DstHost.ToHostAddr()

	sv := getSecretValue()
	reply, err := Level2KeyBuildReply(h.IA, srcIA, dstIA, sv,
		drkey.Lvl2Type(req.ReqType), req.Protocol, srcHost, dstHost)
	if err != nil {
		log.Error("[DRKeyLevel2ReqHandler] Could not build reply", "err", err)
		return infra.MetricsErrInternal
	}
	if err := h.sendRep(ctx, saddr, reply, r.ID); err != nil {
		log.Error("[DRKeyLevel2ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	log.Debug("CERT_SRV DRKEY level 2 handler STEP 10")
	return infra.MetricsResultOk
}

// Level2KeyBuildReply returns the level 2 drkey reply message
// Needs the level 1 key K_{A->B} in order to derive the level 2 if src AS is us.
// If src AS is not us, will ask the appropriate CS
func Level2KeyBuildReply(ourIA, srcIA, dstIA addr.IA, sv *drkey.DRKeySV, keyType drkey.Lvl2Type,
	protocol string, srcHost, dstHost addr.HostAddr) (reply *drkey_mgmt.DRKeyLvl2Rep, err error) {

	// is it us in the fast path?
	if srcIA.Equal(ourIA) {
		// derive level 1 first:
		var lvl1Key *drkey.DRKeyLvl1
		lvl1Key, err = deriveLvl1Key(srcIA, dstIA, sv)
		if err != nil {
			err = common.NewBasicError("Cannot derive DRKey level 1 (from level 2 derivation)", err)
			return
		}
		// derive level 2
		var key *drkey.DRKeyLvl2
		key, err = deriveLvl2Key(lvl1Key, keyType, protocol, srcHost, dstHost)
		if err == nil {
			reply = &drkey_mgmt.DRKeyLvl2Rep{
				Timestamp:  uint32(time.Now().Unix()),
				DRKey:      key.Key,
				EpochBegin: key.Epoch.Begin,
				EpochEnd:   key.Epoch.End,
			}
		}
		return
	} else {
		// check DB and request other CS
		panic("TODO drkeytest: not yet implemented")
	}
	// return
}

// deriveLvl2Key derives the level 2 DRKey
func deriveLvl2Key(lvl1Key *drkey.DRKeyLvl1, keyType drkey.Lvl2Type, protocol string,
	srcHost, dstHost addr.HostAddr) (*drkey.DRKeyLvl2, error) {

	key := drkey.DRKeyLvl2{
		DRKeyLvl1: *lvl1Key,
		KeyType:   keyType,
		Protocol:  protocol,
		SrcHost:   srcHost,
		DstHost:   dstHost,
	}
	if err := key.SetKey(lvl1Key.Key); err != nil {
		return nil, common.NewBasicError("Cannot derive Level 2 DRKey", err)
	}
	return &key, nil
}

func (h *Level2ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl2Rep, id uint64) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError("[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl2(ctx, rep)
}
