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
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ periodic.Task = (*Requester)(nil)

// Requester is in charge of getting the level 1 keys before they expire.
type Requester struct {
	Msgr        infra.Messenger
	State       *config.State
	IA          addr.IA
	PendingASes pendingASes
}

// Run requests the level 1 keys to other CSs.
func (r *Requester) Run(ctx context.Context) {
	// update pending ASes list
	err := r.UpdatePendingList(ctx)
	if err != nil {
		log.Error("[drkey.Run] Error updating pending level 1 keys", "err", err)
	}
	// obtain level 1 for each pending AS
	err = r.ProcessPendingList(ctx)
	if err != nil {
		log.Error("[drkey.Run] Error requesting pending level 1 keys", "err", err)
	}
}

// UpdatePendingList returns the list of ASes we have to query for their level 1 keys.
func (r *Requester) UpdatePendingList(ctx context.Context) error {
	// get ASes from DRKey store
	asesFromDRKeyStore, err := r.getLvl1SrcIAsFromKeystore(ctx)
	if err != nil {
		return common.NewBasicError("[drkey.Requester] failed to get all IAs from DB", err)
	}
	// get ASes from the trustDB
	var asesFromTrustDB asSet // TODO(juagargi): get all known ASes (from trust DB ?)
	// unite the two sets
	pendingASes := unionSet(asesFromDRKeyStore, asesFromTrustDB)
	// up to date ASes from DRKey store
	asesOkFromDRKeyStore, err := r.getValidLvl1SrcIAsFromStore(ctx)
	if err != nil {
		return common.NewBasicError("[drkey.Requester] failed to get valid IAs from DB", err)
	}
	// remove ourselves
	delete(pendingASes, r.IA)
	// difference of previous set with up to date level 1 keys from DB
	r.PendingASes.Set(differenceSet(pendingASes, asesOkFromDRKeyStore))
	return nil
}

// ProcessPendingList should request an level 1 key for each one of the pending ASes.
func (r *Requester) ProcessPendingList(ctx context.Context) error {
	errors := []error{}
	// get pending ASes
	timePoint := uint32(time.Now().Unix()) // TODO(juagargi): this is not enough!
	pending := r.PendingASes.Get()
	for p := range pending {
		// for each one, request their certificates
		err := r.requestLvl1(ctx, p, timePoint)
		if err != nil {
			errors = append(errors, err)
		}
	}
	var err error
	if len(errors) > 0 {
		params := []interface{}{}
		for _, e := range errors {
			params = append(params, "err", e)
		}
		err = common.NewBasicError("Errors requesting level 1 keys", nil, params...)
	}
	return err
}

// getLvl1SrcIAsFromKeystore returns a set of IAs seen as sources in level 1 keys in the DB.
func (r *Requester) getLvl1SrcIAsFromKeystore(ctx context.Context) (asSet, error) {
	list, err := r.State.DRKeyStore.GetLvl1SrcASes(ctx)
	if err != nil && err != sql.ErrNoRows {
		return nil, common.NewBasicError("Cannot obtain DRKey level 1 src IAs from DB", err)
	}
	return setFromList(list), nil
}

// getValidLvl1SrcIAsFromStore returns the set of IAs seen in the store that are still valid.
func (r *Requester) getValidLvl1SrcIAsFromStore(ctx context.Context) (asSet, error) {
	// TODO(juagargi): that 60 should be a configuration parameter
	futurePointInTime := uint32(time.Now().Unix()) + uint32(60)
	list, err := r.State.DRKeyStore.GetValidLvl1SrcASes(ctx, futurePointInTime)
	if err != nil && err != sql.ErrNoRows {
		return nil, common.NewBasicError("Cannot obtain still valid DRKey level 1 src IAs from DB", err)
	}
	return setFromList(list), nil
}

// requestLvl1 will obtain a level 1 key from another CS.
func (r *Requester) requestLvl1(ctx context.Context, pending addr.IA, valTime uint32) error {
	csAddr := &snet.Addr{
		IA:   pending,
		Host: addr.NewSVCUDPAppAddr(addr.SvcCS),
	}
	req := drkey_mgmt.NewLvl1Req(pending, valTime)
	reply, err := r.Msgr.RequestDRKeyLvl1(ctx, &req, csAddr, messenger.NextId())
	if err != nil {
		return err
	}
	// TODO(juagargi): we have a handler for level 1 replies. Can we send the request and return ?
	return r.processReply(ctx, reply, pending)
}

// processReply decrypts the reply and extracts the level 1 key in it.
func (r *Requester) processReply(ctx context.Context, reply *drkey_mgmt.Lvl1Rep, srcIA addr.IA) error {
	// Get the newest certificate for the remote AS
	if reply == nil {
		return common.NewBasicError("reply was empty (nil)", nil)
	}
	dstIA := reply.DstIA()
	chain, err := obtainChain(ctx, dstIA, reply.CertVerDst, r.State.TrustDB, r.Msgr)
	if err != nil {
		return common.NewBasicError("Error obtaining cert. chain", err, "IA", dstIA)
	}
	privateKey := r.State.GetDecryptKey()
	key, err := lvl1KeyFromReply(reply, srcIA, chain.Leaf, privateKey)
	if err != nil {
		return common.NewBasicError("error processing reply", err, "srcIA", srcIA)
	}
	// now store key!
	err = r.State.DRKeyStore.InsertLvl1Key(ctx, key)
	return err
}

// asSet is a set of ASes. In this structure, an AS can be included, or not, in the set.
type asSet map[addr.IA]struct{}

func (s *asSet) String() string {
	ases := make([]string, len(*s))
	for a := range *s {
		ases = append(ases, a.String())
	}
	return strings.Join(ases, ", ")
}

// pendingASes keeps the AS list for which we have to request their level 1 DRKey.
type pendingASes struct {
	set     asSet
	setLock sync.Mutex
}

// Set copies the argument as the pending set.
func (p *pendingASes) Set(pending asSet) {
	p.setLock.Lock()
	defer p.setLock.Unlock()
	p.set = asSet{}
	for i := range pending {
		p.set[i] = struct{}{}
	}
}

// Get returns a copy of the pending ASes.
func (p *pendingASes) Get() asSet {
	p.setLock.Lock()
	defer p.setLock.Unlock()
	ret := make(asSet)
	for i := range p.set {
		ret[i] = struct{}{}
	}
	return ret
}

// unionSet returns the union of the two sets.
func unionSet(a, b asSet) asSet {
	union := make(asSet)
	for i := range a {
		union[i] = struct{}{}
	}
	for i := range b {
		union[i] = struct{}{}
	}
	return union
}

// differenceSet computes the set difference A - B : elements of A not in B .
func differenceSet(a, b asSet) asSet {
	diff := make(asSet)
	for i := range a {
		diff[i] = struct{}{}
	}
	for i := range b {
		delete(diff, i)
	}
	return diff
}

// setFromList returns a set built from a slice.
func setFromList(l []addr.IA) asSet {
	ret := asSet{}
	for _, i := range l {
		ret[i] = struct{}{}
	}
	return ret
}
