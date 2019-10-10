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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// ServiceStore keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type ServiceStore struct {
	localIA      addr.IA
	db           drkey.Lvl1DB
	secretValues drkeystorage.SecretValueFactory
	trustDB      trustdb.TrustDB
	asDecryptKey common.RawBytes
	msger        infra.Messenger
	// allowedDSs is a set of protocols per IP address (in 16 byte form). Represents the allowed
	// protocols hosts can obtain delegation secrets for.
	allowedDSs map[[16]byte]map[string]struct{}
}

var _ drkeystorage.ServiceStore = &ServiceStore{}

// NewServiceStore constructs a DRKey ServiceStore.
func NewServiceStore(local addr.IA, asDecryptKey common.RawBytes, db drkey.Lvl1DB,
	trustDB trustdb.TrustDB, svFac drkeystorage.SecretValueFactory,
	allowedDS map[[16]byte]map[string]struct{}) *ServiceStore {

	return &ServiceStore{
		localIA:      local,
		asDecryptKey: asDecryptKey,
		db:           db,
		secretValues: svFac,
		trustDB:      trustDB,
		allowedDSs:   allowedDS,
	}
}

// SetMessenger sets the messenter. Only callable once.
func (s *ServiceStore) SetMessenger(msger infra.Messenger) {
	if s.msger != nil {
		panic("messenger already set")
	}
	s.msger = msger
}

// GetLvl1Key returns the level 1 drkey from the local DB or if not found, by asking any CS in
// the source AS of the key.
func (s *ServiceStore) GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta,
	valTime time.Time) (drkey.Lvl1Key, error) {

	if meta.SrcIA == s.localIA {
		return s.deriveLvl1(meta.DstIA, valTime)
	}
	// look in the DB
	k, err := s.db.GetLvl1Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot retrieve key from DB", err)
	}
	// get it from another server
	k, err = s.getLvl1FromOtherCS(ctx, meta.SrcIA, meta.DstIA, valTime)
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot obtain level 1 key from CS", err)
	}
	// keep it in our DB
	err = s.db.InsertLvl1Key(ctx, k)
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot store obtained key in DB", err)
	}
	return k, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ServiceStore) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.db.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now()))
	return int(i), err
}

// NewLvl1ReqHandler returns an infra.Handler for level 1 drkey requests coming from a
// peer, backed by the trust store. This method should only be used when servicing
// requests coming from remote nodes.
func (s *ServiceStore) NewLvl1ReqHandler() infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &lvl1ReqHandler{
			request: r,
			store:   s,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewLvl2ReqHandler returns an infra.Handler for level 1 drkey requests coming from a
// peer, backed by the trust store. This method should only be used when servicing
// requests coming from remote nodes.
func (s *ServiceStore) NewLvl2ReqHandler() infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &lvl2ReqHandler{
			request: r,
			store:   s,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// KnownASes returns a list with distinct AS seen as sources in level 1 DRKeys.
func (s *ServiceStore) KnownASes(ctx context.Context) ([]addr.IA, error) {
	return s.db.GetLvl1SrcASes(ctx)
}

func (s *ServiceStore) deriveLvl1(dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error) {
	log.Trace("[DRKey ServiceStore] deriving level 1", "dstIA", dstIA)
	sv, err := s.secretValues.GetSecretValue(valTime)
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Unable to get secret value", err)
	}
	meta := drkey.Lvl1Meta{
		Epoch: sv.Epoch,
		SrcIA: s.localIA,
		DstIA: dstIA,
	}
	key, err := protocol.DeriveLvl1(meta, sv)
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Unable to derive level 1 key", err)
	}
	return key, nil
}

// getLvl1FromOtherCS queries a CS for a level 1 key.
func (s *ServiceStore) getLvl1FromOtherCS(ctx context.Context, srcIA, dstIA addr.IA,
	valTime time.Time) (drkey.Lvl1Key, error) {

	remoteChain, err := s.getCertChain(ctx, srcIA, scrypto.LatestVer)
	if err != nil {
		return drkey.Lvl1Key{},
			common.NewBasicError("Unable to fetch certificate for remote host", err)
	}
	csAddr := &snet.Addr{IA: srcIA, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	lvl1Req := drkey_mgmt.NewLvl1Req(dstIA, util.TimeToSecs(valTime))
	lvl1Rep, err := s.msger.RequestDRKeyLvl1(ctx, &lvl1Req, csAddr, messenger.NextId())
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Error requesting level 1 key to CS", err,
			"cs addr", csAddr)
	}
	lvl1Key, err := getLvl1KeyFromReply(lvl1Rep, srcIA, remoteChain.Leaf, s.asDecryptKey)
	if err != nil {
		return drkey.Lvl1Key{}, common.NewBasicError("Cannot obtain level 1 key from reply", err)
	}
	return lvl1Key, nil
}

// getCertChain gets the certificate chain for the AS from DB, or queries that remote CS. It can
// be called with version=scrypto.LatestVer to get the latest version.
func (s *ServiceStore) getCertChain(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	var chain *cert.Chain
	var err error
	if version == scrypto.LatestVer {
		chain, err = s.trustDB.GetChainMaxVersion(ctx, ia)
	} else {
		chain, err = s.trustDB.GetChainVersion(ctx, ia, version)
	}
	if err != nil {
		return nil, common.NewBasicError("Error in trust DB while getting certificate for AS", err)
	}
	if chain != nil {
		return chain, nil
	}
	chainReq := &cert_mgmt.ChainReq{
		RawIA:     ia.IAInt(),
		Version:   version,
		CacheOnly: true,
	}
	csAddr := &snet.Addr{IA: ia, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	reply, err := s.msger.GetCertChain(ctx, chainReq, csAddr, messenger.NextId())
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
	return chain, nil
}

// getLvl1KeyFromReply decrypts and extracts the level 1 drkey from the reply.
func getLvl1KeyFromReply(reply *drkey_mgmt.Lvl1Rep, srcIA addr.IA, cert *cert.Certificate,
	privateKey common.RawBytes) (drkey.Lvl1Key, error) {

	lvl1Key, err := drkey.DecryptDRKeyLvl1(reply.Cipher, reply.Nonce, cert.SubjectEncKey, privateKey)
	if err != nil {
		return lvl1Key, common.NewBasicError("Error decrypting the key from the reply", err)
	}
	log.Trace("[DRKey ServiceStore] DRKey received")
	lvl1Key.Epoch = reply.Epoch()
	return lvl1Key, nil
}

// lvl1ReqHandler contains the necessary info to process a level 1 drkey request.
type lvl1ReqHandler struct {
	request *infra.Request
	store   *ServiceStore
}

// Handle receives a level 1 request and returns a level 1 reply via the
// infra.Messenger in the store.
func (h *lvl1ReqHandler) Handle() *infra.HandlerResult {
	log.Trace("[DRKey ServiceStore.lvl1ReqHandler] got request")
	ctx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	if err := h.validate(); err != nil {
		log.Error("[DRKey ServiceStore.lvl1ReqHandler] Error validating request", "err", err)
		return infra.MetricsErrInvalid
	}
	saddr := h.request.Peer.(*snet.Addr)
	req := h.request.Message.(*drkey_mgmt.Lvl1Req)
	dstIA := req.DstIA()
	log.Trace("[DRKey ServiceStore.lvl1ReqHandler] Received request", "dstIA", dstIA)
	lvl1Key, err := h.store.deriveLvl1(dstIA, req.ValTime())
	if err != nil {
		log.Error("[DRKey ServiceStore.lvl1ReqHandler] Error deriving level 1 key", "err", err)
		return infra.MetricsErrInternal
	}
	// Get the newest certificate for the remote AS
	dstChain, err := h.store.getCertChain(ctx, dstIA, scrypto.LatestVer)
	if err != nil {
		log.Error("[DRKey ServiceStore.lvl1ReqHandler] Unable to fetch certificate for remote AS",
			"err", err)
		return infra.MetricsErrTrustStore(err)
	}

	reply, err := h.buildReply(lvl1Key, dstChain.Leaf)
	if err != nil {
		log.Error("[DRKey ServiceStore.lvl1ReqHandler] Error building reply", "err", err)
		return infra.MetricsErrInternal
	}
	if err := h.sendRep(ctx, saddr, &reply); err != nil {
		log.Error("[DRKey ServiceStore.lvl1ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// validate checks that the request is well formed.
func (h *lvl1ReqHandler) validate() error {
	req := h.request.Message.(*drkey_mgmt.Lvl1Req)
	if req == nil {
		return common.NewBasicError("Request is NULL", nil,
			"type(req)", fmt.Sprintf("%T", h.request.Message))
	}
	return nil
}

// buildReply constructs the level 1 key exchange reply message:
// cipher = {A | B | K_{A->B}}_PK_B
func (h *lvl1ReqHandler) buildReply(key drkey.Lvl1Key, remoteCert *cert.Certificate) (
	drkey_mgmt.Lvl1Rep, error) {

	nonce, err := scrypto.Nonce(24)
	if err != nil {
		return drkey_mgmt.Lvl1Rep{},
			common.NewBasicError("Unable to get random nonce", err)
	}
	cipher, err := drkey.EncryptDRKeyLvl1(key, nonce, remoteCert.SubjectEncKey,
		h.store.asDecryptKey)
	if err != nil {
		return drkey_mgmt.Lvl1Rep{}, common.NewBasicError("Unable to encrypt drkey", err)
	}
	reply := drkey_mgmt.Lvl1Rep{
		DstIARaw:     key.DstIA.IAInt(),
		EpochBegin:   util.TimeToSecs(key.Epoch.Begin),
		EpochEnd:     util.TimeToSecs(key.Epoch.End),
		Cipher:       cipher,
		Nonce:        nonce,
		CertVerDst:   remoteCert.Version,
		TimestampRaw: util.TimeToSecs(time.Now()),
	}
	return reply, nil
}

// sendRep sends a level 1 reply to the requesting source.
func (h *lvl1ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.Lvl1Rep,
) error {

	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError("Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl1(ctx, rep)
}

// lvl2ReqHandler contains the necessary information to handle a level 2 drkey request.
type lvl2ReqHandler struct {
	request *infra.Request
	store   *ServiceStore
}

// Handle receives a level 2 drkey request and sends a reply using the messenger in its store.
func (h *lvl2ReqHandler) Handle() *infra.HandlerResult {
	log.Trace("[DRKey ServiceStore.lvl2ReqHandler] got request")
	ctx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	if err := h.validate(); err != nil {
		log.Error("[DRKey ServiceStore.lvl2ReqHandler] Error validating request", "err", err)
		return infra.MetricsErrInvalid
	}
	saddr := h.request.Peer.(*snet.Addr)
	req := h.request.Message.(*drkey_mgmt.Lvl2Req)
	srcIA := req.SrcIA()
	dstIA := req.DstIA()
	log.Trace("[DRKey ServiceStore.lvl2ReqHandler] Received request",
		"protocol", req.Protocol, "dstIA", dstIA)

	lvl1Meta := drkey.Lvl1Meta{
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	lvl1Key, err := h.store.GetLvl1Key(ctx, lvl1Meta, req.ValTime())
	if err != nil {
		log.Error("[DRKey ServiceStore.lvl2ReqHandler] Error getting the level 1 key",
			"err", err)
		return infra.MetricsErrInternal
	}
	lvl2Meta := drkey.Lvl2Meta{
		Epoch:    lvl1Key.Epoch,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		KeyType:  drkey.Lvl2KeyType(req.ReqType),
		Protocol: req.Protocol,
		SrcHost:  req.SrcHost.ToHostAddr(),
		DstHost:  req.DstHost.ToHostAddr(),
	}
	lvl2Key, err := h.deriveLvl2(lvl2Meta, lvl1Key)
	if err != nil {
		log.Error("[DRKey ServiceStore.lvl2ReqHandler] Error deriving level 2 key", "err", err)
		return infra.MetricsErrInternal
	}

	reply := drkey_mgmt.NewLvl2RepFromKey(lvl2Key, time.Now())
	if err := h.sendRep(ctx, saddr, reply); err != nil {
		log.Error("[DRKey ServiceStore.lvl2ReqHandler] Unable to send drkey reply", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

// validate checks that the requester is in the destination of the key if AS2Host or host2host,
// and checks that the requester is authorized as to get a DS if AS2AS (AS2AS == DS).
func (h *lvl2ReqHandler) validate() error {
	req := h.request.Message.(*drkey_mgmt.Lvl2Req)
	if req == nil {
		return common.NewBasicError("Request is NULL", nil,
			"type(req)", fmt.Sprintf("%T", h.request.Message))
	}
	// TODO(juagargi) do the checks depending on the key type
	saddr, ok := h.request.Peer.(*snet.Addr)
	if !ok {
		return common.NewBasicError("Requester does not have a SCION address", nil)
	}
	localAddr := saddr.Host.L3
	log.Trace("lvl2ReqHandler validate", "saddr", saddr.String(), "localAddr", localAddr)
	switch drkey.Lvl2KeyType(req.ReqType) {
	case drkey.Host2Host:
		if localAddr.Equal(req.SrcHost.ToHostAddr()) {
			break
		}
		fallthrough
	case drkey.AS2Host:
		if localAddr.Equal(req.DstHost.ToHostAddr()) {
			break
		}
		fallthrough
	case drkey.AS2AS:
		// check in the allowed endhosts list
		var rawIP [16]byte
		copy(rawIP[:], localAddr.IP().To16())
		protocolSet, foundSet := h.store.allowedDSs[rawIP]
		if foundSet {
			if _, found := protocolSet[req.Protocol]; found {
				log.Trace("Authorized delegated secret", "ReqType", req.ReqType,
					"requester address", localAddr, "SrcHost", req.SrcHost.ToHostAddr().String(),
					"DstHost", req.DstHost.ToHostAddr().String())
				return nil
			}
		}
		return common.NewBasicError("Endhost not allowed for DRKey request", nil,
			"ReqType", req.ReqType, "endhost address", localAddr,
			"SrcHost", req.SrcHost.ToHostAddr().String(),
			"DstHost", req.DstHost.ToHostAddr().String())
	default:
		return common.NewBasicError("Unknown request type", nil, "ReqType", req.ReqType)
	}
	return nil
}

// deriveLvl2 will derive the level 2 key specified by the meta data and the level 1 key.
func (h *lvl2ReqHandler) deriveLvl2(meta drkey.Lvl2Meta, lvl1Key drkey.Lvl1Key) (
	drkey.Lvl2Key, error) {

	der, found := protocol.KnownDerivations[meta.Protocol]
	if !found {
		return drkey.Lvl2Key{}, fmt.Errorf("No derivation found for protocol \"%s\"", meta.Protocol)
	}
	return der.DeriveLvl2(meta, lvl1Key)
}

// sendRep takes a level 2 drkey reply and sends it.
func (h *lvl2ReqHandler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.Lvl2Rep) error {
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		return common.NewBasicError("Unable to service request, no messenger found", nil)
	}
	return rw.SendDRKeyLvl2(ctx, rep)
}
