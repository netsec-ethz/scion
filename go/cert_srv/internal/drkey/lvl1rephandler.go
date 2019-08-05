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
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// Lvl1ReplyHandler handles first-level drkey replies.
type Lvl1ReplyHandler struct {
	State       *config.State
	Msger       infra.Messenger
	MaxReplyAge time.Duration
}

// Handle handles the a level drkey reply
func (h *Lvl1ReplyHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()

	saddr := r.Peer.(*snet.Addr)
	srcIA := saddr.IA
	reply := r.Message.(*drkey_mgmt.Lvl1Rep)
	log.Trace("[Lvl1ReplyHandler] Received drkey lvl1 reply", "addr", saddr, "reply", reply)
	if reply == nil {
		log.Error("[Lvl1ReplyHandler] Reply is null after cast")
		return infra.MetricsErrInternal
	}
	if err := h.validateReply(reply, srcIA); err != nil {
		log.Error("[Lvl1ReplyHandler] Reply validation failed", "err", err)
		return infra.MetricsErrInternal
	}
	chain, err := obtainChain(ctx, reply.DstIA(), reply.CertVerDst, h.State.TrustDB, h.Msger)
	if err != nil {
		log.Error("[Lvl1ReplyHandler] Unable to fetch certificate for remote host", "err", err)
		return infra.MetricsErrInternal
	}
	privateKey := h.State.GetDecryptKey()

	key, err := lvl1KeyFromReply(reply, srcIA, chain.Leaf, privateKey)
	// because we received a reply, we probably want to keep a copy in our local DB:
	err = h.State.DRKeyStore.InsertLvl1Key(ctx, key)
	if err != nil {
		log.Error("[Lvl1ReplyHandler] Could not insert the DR key in the DB", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

func (h *Lvl1ReplyHandler) validateReply(reply *drkey_mgmt.Lvl1Rep, srcIA addr.IA) error {
	log.Trace("[Lvl1ReplyHandler] Validating drkey lvl1 reply", "reply", reply)
	if reply == nil {
		return common.NewBasicError("Level 1 reply is NULL", nil)
	}
	now := time.Now()
	if util.TimeDistance(reply.Timestamp(), now) > 42*time.Hour {
		return common.NewBasicError("Reply is too old", nil, "reply", reply.Timestamp(), "now", now)
	}
	// TODO(ben): validate reply (validity time, etc.)
	return nil
}

// lvl1KeyFromReply validates a level 1 reply and returns the level 1 key embedded in it
func lvl1KeyFromReply(reply *drkey_mgmt.Lvl1Rep, srcIA addr.IA, cert *cert.Certificate,
	privateKey common.RawBytes) (drkey.Lvl1Key, error) {

	// TODO(juagargi): match this reply with a request from this CS
	lvl1Key, err := drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		return lvl1Key, common.NewBasicError("Error decrypting the key from the reply", err)
	}
	log.Trace("[lvl1KeyFromReply] DRKey received")
	lvl1Key.Epoch = reply.Epoch()
	return lvl1Key, nil
}
