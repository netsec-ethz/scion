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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
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
	State *csconfig.State
	IA    addr.IA
}

// Handle handles the level 1 drkey requests
func (h *Level1ReqHandler) Handle(r *infra.Request) {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	srcIA := saddr.IA
	dstIA := req.SrcIa.IA()

	// TODO: drkeytest: add the SV to the configuration
	var TODOSV drkey.DRKeySV

	// Get the newest certificate for the remote host
	cert, err := h.State.TrustDB.GetLeafCertMaxVersion(ctx, req.IA())
	if err != nil {
		log.Error("[DRKeyLevel1ReqHandler] Unable to fetch certificate for remote host", "err", err)
		return
	}
	privateKey := h.State.GetDecryptKey()
	reply, err := Level1KeyBuildReply(srcIA, dstIA, TODOSV, cert, privateKey)
	if err != nil {
		log.Error("[DRKeyLevel1ReqHandler]", "err", err)
		return
	}

	if err := h.sendRep(ctx, saddr, reply, r.ID); err != nil {
		log.Error("[DRKeyLevel1ReqHandler] Unable to send drkey reply", "err", err)
	}
}

// Level1KeyBuildReply constructs the level 1 key exchange reply message
// cipher = {A | B | K_{A->B}}_PK_B
// nonce = nonce
// Epoch comes from the secret value (configuration)
func Level1KeyBuildReply(srcIA, dstIA addr.IA, sv drkey.DRKeySV, cert *cert.Certificate, privateKey common.RawBytes) (reply *drkey_mgmt.DRKeyLvl1Rep, err error) {
	log.Debug("Received drkey lvl1 request", "srcIA", srcIA, "dstIA", dstIA)

	if err = validateReq(srcIA, dstIA); err != nil {
		err = fmt.Errorf("Dropping DRKeyLvl1 request, validation error: %v", err)
		return
	}

	key, err := deriveKey(srcIA, dstIA, sv)
	if err != nil {
		err = fmt.Errorf("Unable to derive drkey: %v", err)
		return
	}

	nonce, err := scrypto.Nonce(24)
	if err != nil {
		err = fmt.Errorf("Unable to get random nonce drkey: %v", err)
		return
	}
	cipher, err := drkey.EncryptDRKeyLvl1(key, nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		err = fmt.Errorf("Unable to encrypt drkey: %v", err)
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

func deriveKey(srcIA, dstIA addr.IA, sv drkey.DRKeySV) (*drkey.DRKeyLvl1, error) {
	// TODO(ben): remove
	log.Debug("[DRKeyReqHandler] Deriving drkey for lvl1 request", "srcIA", srcIA, "dstIA", dstIA)
	key := &drkey.DRKeyLvl1{
		SrcIa: srcIA,
		DstIa: dstIA,
		Epoch: sv.Epoch,
	}
	if err := key.SetKey(sv.Key); err != nil {
		return nil, err
	}
	return key, nil
}

func (h *Level1ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl1Rep, id uint64) error {
	msger, ok := infra.MessengerFromContext(ctx)
	if !ok {
		return common.NewBasicError(
			"[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return msger.SendDRKeyLvl1(ctx, rep, addr, id)
}

// Level1ReplyHandler handles first-level drkey replies.
type Level1ReplyHandler struct {
	State *csconfig.State
}

// Handle handles the a level drkey reply
func (h *Level1ReplyHandler) Handle(r *infra.Request) {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()

	saddr := r.Peer.(*snet.Addr)
	reply := r.Message.(*drkey_mgmt.DRKeyLvl1Rep)
	log.Debug("[Level1ReplyHandler] Received drkey lvl1 reply", "addr", saddr, "reply", reply)
	if reply == nil {
		log.Error("[Level1ReplyHandler] Reply is null after cast")
		return
	}
	cert, err := h.State.TrustDB.GetLeafCertMaxVersion(ctx, reply.IA())
	if err != nil {
		log.Error("[Level1ReplyHandler] Unable to fetch certificate for remote host", "err", err)
		return
	}
	privateKey := h.State.GetDecryptKey()

	key, err := Level1KeyFromReply(reply, saddr.IA, cert, privateKey)
	_, err = h.State.DrkeyStore.InsertDRKeyLvl1Ctx(ctx, key)
	if err != nil {
		log.Error("[Level1ReplyHandler] Could not insert the DR key in the DB", "err", err)
		return
	}
}

// Level1KeyFromReply validates a level 1 reply and returns the level 1 key embedded in it
func Level1KeyFromReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA, cert *cert.Certificate, privateKey common.RawBytes) (key *drkey.DRKeyLvl1, err error) {
	if err = validateReply(reply, srcIA); err != nil {
		err = fmt.Errorf("Dropping DRKeyLvl1 reply: %v", err)
		return
	}
	// TODO(juan): match this reply with a request from this CS
	key, err = drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		err = fmt.Errorf("Error decrypting the key from the reply: %v", err)
		return
	}
	log.Debug("[Level1ReplyHandler] DRKey received", "key", key)
	key.Epoch = reply.Epoch()

	return
}

func validateReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA) error {
	// TODO(ben): validate reply (validity time, etc.)
	log.Debug("[Level1ReplyHandler] Validating drkey lvl1 reply", "reply", reply)
	if !srcIA.Eq(reply.SrcIa.IA()) {
		return common.NewBasicError(AddressMismatchError, nil, "expected", srcIA, "actual", reply.SrcIa.IA())
	}
	return nil
}
