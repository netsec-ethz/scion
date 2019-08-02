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
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	DRKeyHandlerTimeout = 5 * time.Second
)

// Lvl1ReqHandler handles first-level drkey requests.
type Lvl1ReqHandler struct {
	State *config.State
	IA    addr.IA
	Msger infra.Messenger
}

// Handle handles the level 1 drkey requests
func (h *Lvl1ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	srcIA := h.IA // always us
	dstIA := req.DstIA()
	log.Trace("[DRKeyLvl1ReqHandler] Received request", "srcIA", srcIA, "dstIA", dstIA)

	sv, err := h.State.DRKeyStore.SecretValue(req.ValTime())
	if err != nil {
		log.Error("[DRKeyLvl1ReqHandler] Unable to get secret value", "err", err)
		return infra.MetricsErrInternal
	}
	// Get the newest certificate for the remote AS
	dstChain, err := ObtainChain(ctx, dstIA, h.State.TrustDB, h.Msger)
	if err != nil {
		log.Error("[DRKeyLvl1ReqHandler] Unable to fetch certificate for remote AS", "err", err)
		return infra.MetricsErrInternal
	}

	privateKey := h.State.GetDecryptKey()
	reply, err := Lvl1KeyBuildReply(srcIA, dstIA, sv, dstChain.Leaf, privateKey)
	if err != nil {
		log.Error("[DRKeyLvl1ReqHandler]", "err", err)
		return infra.MetricsErrInternal
	}

	if err := h.sendRep(ctx, saddr, reply, r.ID); err != nil {
		log.Error("[DRKeyLvl1ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// ObtainChain gets the certificate chain for the AS from DB, or queries that remote CS
func ObtainChain(ctx context.Context, ia addr.IA, trustDB trustdb.TrustDB, msger infra.Messenger) (*cert.Chain, error) {
	chain, err := trustDB.GetChainMaxVersion(ctx, ia)
	if err != nil {
		return nil, common.NewBasicError("Error getting certificate for AS", err)

	}
	if chain == nil {
		// we don't have it
		// TODO(juagargi): plese review this request
		chainReq := &cert_mgmt.ChainReq{
			RawIA:     ia.IAInt(),
			Version:   scrypto.LatestVer,
			CacheOnly: true,
		}
		csAddr := &snet.Addr{IA: ia, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
		reply, err := msger.GetCertChain(ctx, chainReq, csAddr, messenger.NextId())
		if err != nil {
			return nil, common.NewBasicError("Could not query CS for certificate", err, "remote CS", csAddr)
		}
		chain, err = reply.Chain()
		if err != nil {
			return nil, common.NewBasicError("could not unpack the certificate reply response", err)
		}
		if chain == nil {
			return nil, common.NewBasicError("The certificate chain is null", nil, "remote CS", csAddr)
		}
	}
	return chain, nil
}

// Lvl1KeyBuildReply constructs the level 1 key exchange reply message
// cipher = {A | B | K_{A->B}}_PK_B
// nonce = nonce
// Epoch comes from the secret value (configuration)
func Lvl1KeyBuildReply(srcIA, dstIA addr.IA, sv *drkey.SV, cert *cert.Certificate, privateKey common.RawBytes) (reply *drkey_mgmt.DRKeyLvl1Rep, err error) {
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

	reply = &drkey_mgmt.DRKeyLvl1Rep{
		DstIARaw:   dstIA.IAInt(),
		EpochBegin: sv.Epoch.BeginAsSeconds(),
		EpochEnd:   sv.Epoch.EndAsSeconds(),
		Cipher:     cipher,
		Nonce:      nonce,
		CertVerDst: cert.Version,
	}
	return
}

func validateReq(srcIA, dstIA addr.IA) error {
	// TODO(ben): validate request (validity time, etc.)
	// TODO(ben): remove
	log.Trace("[DRKeyReqHandler] Validating drkey lvl1 request", "src", srcIA, "dst", dstIA)
	// if !srcIA.Eq(req.SrcIa.IA()) {
	// 	return common.NewBasicError(AddressMismatchError, nil,
	// 		"expected", addr.IA, "actual", req.SrcIa.IA())
	// }
	return nil
}

func deriveLvl1Key(srcIA, dstIA addr.IA, sv *drkey.SV) (drkey.Lvl1Key, error) {
	log.Trace("[DRKeyReqHandler] Deriving drkey for lvl1", "srcIA", srcIA, "dstIA", dstIA)
	meta := drkey.Lvl1Meta{
		Epoch: sv.Epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	key, err := drkey.NewLvl1Key(meta, *sv)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	return key, nil
}

func (h *Lvl1ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl1Rep, id uint64) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError(
			"[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl1(ctx, rep)
}
