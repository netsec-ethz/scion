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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = (*StoreKeeper)(nil)

// StoreKeeper is in charge of keeping the DB clean of expired entries
type StoreKeeper struct {
	State *config.State
}

// Run keeps the expired DRKeys out of the DB
func (k *StoreKeeper) Run(ctx context.Context) {
	// add 5m to the current time to leave the keys expiring in the next 5 minutes in the DB
	cutoff := uint32(time.Now().Add(5 * time.Minute).Unix())
	log.Trace("[drkey.StoreKeeper] Runs now", "cutoff", cutoff)
	log.Trace("[drkey.StoreKeeper] Calling RemoveOutDatedDRKeyL1 now")
	count, err := k.State.DRKeyStore.RemoveOutdatedDRKeyLvl1(ctx, cutoff)
	log.Trace("[drkey.StoreKeeper] RemoveOutDatedDRKeyL1 finished", "count", count, "err", err)
	if err != nil {
		log.Error("[drkey.StoreKeeper] Unable to remove outdated L1 keys", "err", err)
	}

	log.Trace("[drkey.StoreKeeper] Calling RemoveOutDatedDRKeyL2 now")
	count, err = k.State.DRKeyStore.RemoveOutdatedDRKeyLvl2(ctx, cutoff)
	log.Trace("[drkey.StoreKeeper] RemoveOutDatedDRKeyL2 finished", "count", count, "err", err)
	if err != nil {
		log.Error("[drkey.StoreKeeper] Unable to remove outdated L2 keys", "err", err)
	}
	log.Trace("[drkey.StoreKeeper] Done", "run time", uint32(time.Now().Unix())-cutoff)
}
