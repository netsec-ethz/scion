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

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
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
	r.UpdatePendingList()
	// obtain L1 for each pending AS
	r.ProcessPendingList()
}

// UpdatePendingList returns the list of ASes we have to query for their L1 keys
func (r *Requester) UpdatePendingList() {
	// get ASes from DRKey store
	var asesFromDRKeyStore asSet // TODO drkeytest
	// get ASes from the trustDB
	var asesFromTrustDB asSet // TODO drkeytest: get all known ASes
	// unite the two sets
	pendingASes := unionSet(asesFromDRKeyStore, asesFromTrustDB)
	// up to date ASes from DRKey store
	var asesOkFromDRKeyStore asSet // TODO drkeytest
	// difference of previous set with up to date L1s from DB
	r.PendingASes.Set(unionDifference(pendingASes, asesOkFromDRKeyStore))
}

// ProcessPendingList should request an L1 key for each one of the pending ASes
func (r *Requester) ProcessPendingList() {
	// TODO drkeytest:
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
