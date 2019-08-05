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
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

// Lvl2ReqHandler contains the information necessary to handle a level 2 drkey request.
type Lvl2ReqHandler struct {
	State    *config.State
	IA       addr.IA
	Msger    infra.Messenger
	ProtoMap *protocol.Map
}

// Handle handles the level 1 drkey requests
func (h *Lvl2ReqHandler) Handle(r *infra.Request) *infra.HandlerResult {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()
	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl2Req)
	log.Debug("[DRKeyLvl2ReqHandler] Received request", "req", req)
	srcIA := req.SrcIA()
	dstIA := req.DstIA()

	// TODO(juagargi): should we always send something, to signal e.g. sciond there was an error, and avoid the timeout?
	// E.g. when we request an AS2Host key but leave the host addr empty, sciond waits until timeout
	sv, err := h.State.DRKeyStore.SecretValue(time.Unix(int64(req.ValTimeRaw), 0))
	if err != nil {
		log.Error("[DRKeyLvl2ReqHandler] Unable to get secret value", "err", err)
		return infra.MetricsErrInternal
	}
	reply, err := h.lvl2KeyBuildReply(ctx, req, srcIA, dstIA, sv)
	if err != nil {
		log.Error("[DRKeyLvl2ReqHandler] Could not build reply", "err", err)
		return infra.MetricsErrInternal
	}
	if err := h.sendRep(ctx, saddr, &reply, r.ID); err != nil {
		log.Error("[DRKeyLvl2ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// lvl2KeyBuildReply returns the level 2 drkey reply message
// Needs the level 1 key K_{A->B} in order to derive the level 2 if src AS is us.
// If src AS is not us, will ask the appropriate CS
func (h *Lvl2ReqHandler) lvl2KeyBuildReply(ctx context.Context, req *drkey_mgmt.DRKeyLvl2Req,
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
		log.Trace("[DRKeyLvl2BuildReply] this AS in the fast path", "SV", sv)
		// derive level 1 first:
		lvl1Key, err = deriveLvl1Key(srcIA, dstIA, sv)
		if err != nil {
			return reply, common.NewBasicError("Cannot derive DRKey level 1 (from level 2 derivation)", err)
		}
	} else {
		log.Trace("[DRKeyLvl2BuildReply] this AS in the slow path")
		// check DB for the level 1 key
		lvl1Key, err = findLvl1KeyInDB(ctx, h.State.DRKeyStore, valTime, srcIA, dstIA)
		if err != nil && err != sql.ErrNoRows {
			return reply, common.NewBasicError("Cannot query the DRKey DB", err)
		}
		if err == nil {
			log.Trace("[DRKeyLvl2BuildReply] found level 1 key in DB for derivation")
		} else {
			log.Trace("[DRKeyLvl2BuildReply] no level 1 key in DB, querying CS")
			// we need to query the CS_{srcIA} for the level 1
			lvl1Key, err = h.getLvl1KeyFromOtherCS(ctx, srcIA, dstIA, valTime)
			if err != nil {
				return reply, common.NewBasicError("Error querying level 1 key from another CS", err)
			}
		}
	}
	log.Trace("[DRKeyLvl2BuildReply] Got level 1 key, about to derive L2")
	// derive level 2
	var lvl2key drkey.Lvl2Key
	lvl2key, err = h.deriveLvl2Key(lvl1Key, keyType, protocol, srcHost, dstHost)
	if err != nil {
		return reply, common.NewBasicError("Cannot derive level 2 drkey from level 1", err)
	}
	log.Trace("[DRKeyLvl2BuildReply] about to save key in DB")
	reply = drkey_mgmt.NewDRKeyLvl2RepFromKeyRepresentation(lvl2key, uint32(time.Now().Unix()))
	// save the key in the DB
	err = storeLvl2KeyInDB(ctx, h.State.DRKeyStore, lvl2key)
	if err != nil {
		return drkey_mgmt.DRKeyLvl2Rep{}, common.NewBasicError("Could not store the level 2 DRKey in the DB", err, "reply", reply)
	}
	return reply, nil
}

func (h *Lvl2ReqHandler) getLvl1KeyFromOtherCS(ctx context.Context, srcIA, dstIA addr.IA,
	valTime uint32) (drkey.Lvl1Key, error) {

	var lvl1Key drkey.Lvl1Key
	chain, err := ObtainChain(ctx, srcIA, h.State.TrustDB, h.Msger)
	if err != nil {
		return lvl1Key, common.NewBasicError("Unable to fetch certificate for remote host", err)
	}
	privateKey := h.State.GetDecryptKey()
	// TODO(juagargi): move this to only request level 1 from a requester (a la reiss.requester)
	csAddr := &snet.Addr{IA: srcIA, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	lvl1Req := drkey_mgmt.NewDRKeyLvl1Req(dstIA, valTime)
	lvl1Rep, err := h.Msger.RequestDRKeyLvl1(ctx, lvl1Req, csAddr, messenger.NextId())
	if err != nil {
		return lvl1Key, err
	}
	lvl1Key, err = lvl1KeyFromReply(lvl1Rep, srcIA, chain.Leaf, privateKey)
	if err != nil {
		return lvl1Key, common.NewBasicError("Cannot obtain level 1 key from reply", err)
	}
	return lvl1Key, nil
}

// deriveLvl2Key derives the level 2 DRKey
func (h *Lvl2ReqHandler) deriveLvl2Key(lvl1Key drkey.Lvl1Key, keyType drkey.Lvl2KeyType, protocol string,
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
	key, err := h.ProtoMap.DeriveLvl2(meta, lvl1Key)
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
	stored, err := db.GetLvl1Key(ctx, meta, valTime)
	if err != nil && err != sql.ErrNoRows {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot query DRKey Store [level 1]", err)
	}
	return stored, err
}

func storeLvl2KeyInDB(ctx context.Context, db drkeystorage.Store, key drkey.Lvl2Key) error {
	err := db.InsertLvl2Key(ctx, key)
	return err
}

func (h *Lvl2ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl2Rep, id uint64) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError("[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl2(ctx, rep)
}
