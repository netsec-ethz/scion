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
	"sync"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey/keystore"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = (*Requester)(nil)

// Requester is in charge of getting the L1 keys before they expire
type Requester struct {
	Msgr        infra.Messenger
	State       *config.State
	IA          addr.IA
	PendingASes pendingL1
}

// Run requests L1 keys from other CSs
func (r *Requester) Run(ctx context.Context) {
	// update pending ASes list
	r.UpdatePendingList(ctx)
	// obtain L1 for each pending AS
	r.ProcessPendingList(ctx)
}

// UpdatePendingList returns the list of ASes we have to query for their L1 keys
func (r *Requester) UpdatePendingList(ctx context.Context) error {
	// get ASes from DRKey store
	asesFromDRKeyStore, err := r.getL1SrcIAsFromKeystore(ctx)
	if err != nil {
		return common.NewBasicError("[drkey.Requester] failed to get all IAs from DB", err)
	}
	// get ASes from the trustDB
	var asesFromTrustDB asSet // TODO drkeytest: get all known ASes (from trust DB ?)
	// unite the two sets
	pendingASes := unionSet(asesFromDRKeyStore, asesFromTrustDB)
	// up to date ASes from DRKey store
	asesOkFromDRKeyStore, err := r.getL1SrcIAsFromKSStillValid(ctx)
	if err != nil {
		return common.NewBasicError("[drkey.Requester] failed to get valid IAs from DB", err)
	}
	// difference of previous set with up to date L1s from DB
	r.PendingASes.Set(unionDifference(pendingASes, asesOkFromDRKeyStore))
	return nil
}

// ProcessPendingList should request an L1 key for each one of the pending ASes
func (r *Requester) ProcessPendingList(ctx context.Context) {
	// TODO drkeytest:
}

// getL1SrcIAsFromKeystore returns a set of IAs seen as sources in L1 keys in the DB
func (r *Requester) getL1SrcIAsFromKeystore(ctx context.Context) (asSet, error) {
	list, err := r.State.DRKeyStore.GetL1SrcASes(ctx)
	if err != nil && err != keystore.ErrNoKeys {
		return nil, common.NewBasicError("Cannot obtain DRKey L1 src IAs from DB", err)
	}
	return setFromList(list), nil
}

func (r *Requester) getL1SrcIAsFromKSStillValid(ctx context.Context) (asSet, error) {
	// TODO drkeytest: that 60 should be a configuration parameter
	futurePointInTime := uint32(time.Now().Unix()) + uint32(60)
	list, err := r.State.DRKeyStore.GetValidL1SrcASes(ctx, futurePointInTime)
	if err != nil && err != keystore.ErrNoKeys {
		return nil, common.NewBasicError("Cannot obtain still valid DRKey L1 src IAs from DB", err)
	}
	return setFromList(list), nil
}

type asSet map[addr.IA]struct{}

// pendingL1 keeps the AS list for which we have to request their L1 DRKey
type pendingL1 struct {
	set     asSet
	setLock sync.Mutex
}

// Set copies the argument as the pending set
func (p *pendingL1) Set(pending asSet) {
	p.setLock.Lock()
	defer p.setLock.Unlock()
	p.set = asSet{}
	for i := range pending {
		p.set[i] = struct{}{}
	}
}

// Get returns a copy of the pending ASes
func (p *pendingL1) Get() asSet {
	p.setLock.Lock()
	defer p.setLock.Unlock()
	ret := make(asSet)
	for i := range p.set {
		ret[i] = struct{}{}
	}
	return ret
}

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

// unionDifference computes the set difference A - B : elements of A not in B
func unionDifference(a, b asSet) asSet {
	diff := make(asSet)
	for i := range a {
		diff[i] = struct{}{}
	}
	for i := range b {
		delete(diff, i)
	}
	return diff
}

func setFromList(l []addr.IA) asSet {
	ret := asSet{}
	for _, i := range l {
		ret[i] = struct{}{}
	}
	return ret
}
