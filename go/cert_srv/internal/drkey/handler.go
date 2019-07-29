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
	"database/sql"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
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
	Msger infra.Messenger
}

// Handle handles the level 1 drkey requests
func (h *Level1ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	srcIA := h.IA // always us
	dstIA := req.DstIA()
	log.Debug("[DRKeyLevel1ReqHandler] Received request", "srcIA", srcIA, "dstIA", dstIA)

	sv, err := h.State.DRKeyStore.SecretValue(req.ValTime())
	if err != nil {
		log.Error("[DRKeyLevel1ReqHandler] Unable to get secret value", "err", err)
		return infra.MetricsErrInternal
	}
	// Get the newest certificate for the remote AS
	dstChain, err := ObtainChain(ctx, dstIA, h.State.TrustDB, h.Msger)
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

// ObtainChain gets the certificate chain for the AS from DB, or queries that remote CS
func ObtainChain(ctx context.Context, ia addr.IA, trustDB trustdb.TrustDB, msger infra.Messenger) (*cert.Chain, error) {
	chain, err := trustDB.GetChainMaxVersion(ctx, ia)
	if err != nil {
		return nil, common.NewBasicError("Error getting certificate for AS", err)

	}
	if chain == nil {
		// we don't have it
		// TODO drkeytest: plese review this request
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

// Level1KeyBuildReply constructs the level 1 key exchange reply message
// cipher = {A | B | K_{A->B}}_PK_B
// nonce = nonce
// Epoch comes from the secret value (configuration)
func Level1KeyBuildReply(srcIA, dstIA addr.IA, sv *drkey.SV, cert *cert.Certificate, privateKey common.RawBytes) (reply *drkey_mgmt.DRKeyLvl1Rep, err error) {
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
	Msger infra.Messenger
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
	chain, err := ObtainChain(ctx, reply.DstIA(), h.State.TrustDB, h.Msger)
	if err != nil {
		log.Error("[Level1ReplyHandler] Unable to fetch certificate for remote host", "err", err)
		return infra.MetricsErrInternal
	}
	privateKey := h.State.GetDecryptKey()

	key, err := Level1KeyFromReply(reply, saddr.IA, chain.Leaf, privateKey)
	// because we received a reply, we probably want to keep a copy in our local DB:
	_, err = h.State.DRKeyStore.InsertDRKeyLvl1(ctx, key)
	if err != nil {
		log.Error("[Level1ReplyHandler] Could not insert the DR key in the DB", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// Level1KeyFromReply validates a level 1 reply and returns the level 1 key embedded in it
func Level1KeyFromReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA, cert *cert.Certificate,
	privateKey common.RawBytes) (drkey.Lvl1Key, error) {

	var lvl1Key drkey.Lvl1Key
	var err error
	if err = validateReply(reply, srcIA); err != nil {
		return lvl1Key, common.NewBasicError("Dropping DRKeyLvl1 reply", err)
	}
	// TODO drkeytest: match this reply with a request from this CS
	lvl1Key, err = drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		return lvl1Key, common.NewBasicError("Error decrypting the key from the reply", err)
	}
	log.Trace("[Level1KeyFromReply] DRKey received")
	lvl1Key.Epoch = reply.Epoch()
	return lvl1Key, nil
}

func validateReply(reply *drkey_mgmt.DRKeyLvl1Rep, srcIA addr.IA) error {
	if reply == nil {
		return common.NewBasicError("L1 reply is NULL", nil)
	}
	// TODO(ben): validate reply (validity time, etc.)
	// log.Debug("[Level1ReplyHandler] Validating drkey lvl1 reply", "reply", reply)
	// if !srcIA.Equal(reply.SrcIa.IA()) {
	// 	return common.NewBasicError(AddressMismatchError, nil, "expected", srcIA, "actual", reply.SrcIa.IA())
	// }
	return nil
}

type Level2ReqHandler struct {
	State *config.State
	IA    addr.IA
	Msger infra.Messenger
}

// Handle handles the level 1 drkey requests
func (h *Level2ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl2Req)
	log.Debug("[DRKeyLevel2ReqHandler] Received request", "req", req)
	srcIA := req.SrcIA()
	dstIA := req.DstIA()

	// TODO drkeytest: should we always send something, to signal e.g. sciond there was an error, and avoid the timeout?
	// E.g. when we request an AS2Host key but leave the host addr empty, sciond waits until timeout
	sv, err := h.State.DRKeyStore.SecretValue(valToTime(req.ValTimeRaw))
	if err != nil {
		log.Error("[DRKeyLevel2ReqHandler] Unable to get secret value", "err", err)
		return infra.MetricsErrInternal
	}
	reply, err := h.level2KeyBuildReply(ctx, req, srcIA, dstIA, sv)
	if err != nil {
		log.Error("[DRKeyLevel2ReqHandler] Could not build reply", "err", err)
		return infra.MetricsErrInternal
	}
	if err := h.sendRep(ctx, saddr, &reply, r.ID); err != nil {
		log.Error("[DRKeyLevel2ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// level2KeyBuildReply returns the level 2 drkey reply message
// Needs the level 1 key K_{A->B} in order to derive the level 2 if src AS is us.
// If src AS is not us, will ask the appropriate CS
func (h *Level2ReqHandler) level2KeyBuildReply(ctx context.Context, req *drkey_mgmt.DRKeyLvl2Req,
	srcIA, dstIA addr.IA, sv *drkey.SV) (drkey_mgmt.DRKeyLvl2Rep, error) {

	var reply drkey_mgmt.DRKeyLvl2Rep
	var err error
	srcHost := req.SrcHost.ToHostAddr()
	dstHost := req.DstHost.ToHostAddr()
	valTime := req.ValTimeRaw
	keyType := drkey.Lvl2KeyType(req.ReqType)
	protocol := req.Protocol
	var lvl1Key drkey.Lvl1Key
	// is it us in the fast path?
	if srcIA.Equal(h.IA) {
		log.Trace("[DRKeyLevel2BuildReply] this AS in the fast path", "SV", sv)
		// derive level 1 first:
		lvl1Key, err = deriveLvl1Key(srcIA, dstIA, sv)
		if err != nil {
			return reply, common.NewBasicError("Cannot derive DRKey level 1 (from level 2 derivation)", err)
		}
	} else {
		log.Trace("[DRKeyLevel2BuildReply] this AS in the slow path")
		// check DB for the L2 key
		var stored drkey.Lvl2Key
		stored, err = findLvl2KeyInDB(ctx, h.State.DRKeyStore, valTime, protocol, keyType, srcIA, dstIA, srcHost, dstHost)
		if err != nil && err != sql.ErrNoRows {
			return reply, common.NewBasicError("Cannot query the DRKey DB", err)
		}
		if err == nil {
			// found the L2 key in the DB
			log.Trace("[DRKeyLevel2BuildReply] found L2 key in DB, returning it")
			return drkey_mgmt.NewDRKeyLvl2RepFromKeyRepresentation(stored, uint32(time.Now().Unix())), nil
		}
		// check DB for the L1 key
		lvl1Key, err = findLvl1KeyInDB(ctx, h.State.DRKeyStore, valTime, srcIA, dstIA)
		if err != nil && err != sql.ErrNoRows {
			return reply, common.NewBasicError("Cannot query the DRKey DB", err)
		}
		if err == nil {
			log.Trace("[DRKeyLevel2BuildReply] found L1 key in DB for derivation")
		} else {
			log.Trace("[DRKeyLevel2BuildReply] no L1 key in DB, querying CS")
			// we need to query the CS_{srcIA} for the L1
			lvl1Key, err = h.getL1KeyFromOtherCS(ctx, srcIA, dstIA, valTime)
			if err != nil {
				return reply, common.NewBasicError("Error querying L1 to another CS", err)
			}
		}
	}
	log.Trace("[DRKeyLevel2BuildReply] Got level 1 key, about to derive L2")
	// derive level 2
	var lvl2key drkey.Lvl2Key
	lvl2key, err = deriveLvl2Key(lvl1Key, keyType, protocol, srcHost, dstHost)
	if err != nil {
		return reply, common.NewBasicError("Cannot derive L2 from L1", err)
	}
	log.Trace("[DRKeyLevel2BuildReply] about to save key in DB")
	reply = drkey_mgmt.NewDRKeyLvl2RepFromKeyRepresentation(lvl2key, uint32(time.Now().Unix()))
	// save the key in the DB
	err = storeLvl2KeyInDB(ctx, h.State.DRKeyStore, lvl2key)
	if err != nil {
		return drkey_mgmt.DRKeyLvl2Rep{}, common.NewBasicError("Could not store the level 2 DRKey in the DB", err, "reply", reply)
	}
	return reply, nil
}

func (h *Level2ReqHandler) getL1KeyFromOtherCS(ctx context.Context, srcIA, dstIA addr.IA,
	valTime uint32) (drkey.Lvl1Key, error) {

	var lvl1Key drkey.Lvl1Key
	chain, err := ObtainChain(ctx, srcIA, h.State.TrustDB, h.Msger)
	if err != nil {
		return lvl1Key, common.NewBasicError("Unable to fetch certificate for remote host", err)
	}
	privateKey := h.State.GetDecryptKey()
	// TODO drkeytest: move this to only request L1 from a requester (a la reiss.requester)
	csAddr := &snet.Addr{IA: srcIA, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	lvl1Req := drkey_mgmt.NewDRKeyLvl1Req(dstIA, valTime)
	lvl1Rep, err := h.Msger.RequestDRKeyLvl1(ctx, lvl1Req, csAddr, messenger.NextId())
	if err != nil {
		return lvl1Key, err
	}
	lvl1Key, err = Level1KeyFromReply(lvl1Rep, srcIA, chain.Leaf, privateKey)
	if err != nil {
		return lvl1Key, common.NewBasicError("Cannot obtain level 1 key from reply", err)
	}
	return lvl1Key, nil
}

// deriveLvl2Key derives the level 2 DRKey
func deriveLvl2Key(lvl1Key drkey.Lvl1Key, keyType drkey.Lvl2KeyType, protocol string,
	srcHost, dstHost addr.HostAddr) (drkey.Lvl2Key, error) {

	meta := drkey.Lvl2Meta{
		KeyType:  keyType,
		Protocol: protocol,
		Epoch:    lvl1Key.Epoch,
		SrcIA:    lvl1Key.SrcIA,
		DstIA:    lvl1Key.DstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	key, err := drkey.NewLvl2Key(meta, lvl1Key)
	if err != nil {
		return key, common.NewBasicError("Cannot derive Level 2 DRKey", err)
	}
	return key, nil
}

func findLvl1KeyInDB(ctx context.Context, db drkeystorage.Store, valTime uint32, srcIA, dstIA addr.IA) (drkey.Lvl1Key, error) {
	meta := drkey.Lvl1Meta{
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	stored, err := db.GetDRKeyLvl1(ctx, meta, valTime)
	if err != nil && err != sql.ErrNoRows {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot query DRKey Store [level1]", err)
	}
	return stored, err
}

func findLvl2KeyInDB(ctx context.Context, db drkeystorage.Store, valTime uint32, protocol string,
	keyType drkey.Lvl2KeyType, srcIA, dstIA addr.IA, srcHost, dstHost addr.HostAddr) (drkey.Lvl2Key, error) {

	key := drkey.Lvl2Meta{
		KeyType:  keyType,
		Protocol: protocol,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	stored, err := db.GetDRKeyLvl2(ctx, key, valTime)
	if err != nil && err != sql.ErrNoRows {
		return drkey.Lvl2Key{}, common.NewBasicError("Cannot query DRKey Store [level2]", err)
	}
	return stored, err
}

func storeLvl2KeyInDB(ctx context.Context, db drkeystorage.Store, key drkey.Lvl2Key) error {
	_, err := db.InsertDRKeyLvl2(ctx, key)
	return err
}

func (h *Level2ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl2Rep, id uint64) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError("[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl2(ctx, rep)
}

func valToTime(v uint32) time.Time {
	return time.Unix(int64(v), 0)
}
