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
	// "fmt"
	// "net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	// "github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	// "github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	// "github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	// "github.com/scionproto/scion/go/lib/log"
	// "github.com/scionproto/scion/go/lib/scrypto"
	// "github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// ClientStore is the DRKey store used in the client side, i.e. sciond.
// It implements drkeystorage.ClientStore.
type ClientStore struct {
	ia    addr.IA
	db    drkey.Lvl2DB
	msger infra.Messenger
}

var _ drkeystorage.ClientStore = &ClientStore{}

// NewClientStore constructs a new client store without assigned messenger.
func NewClientStore(local addr.IA, db drkey.Lvl2DB, msger infra.Messenger) *ClientStore {
	return &ClientStore{
		ia:    local,
		db:    db,
		msger: msger,
	}
}

// GetLvl2Key returns the level 2 drkey from the local DB or if not found, by asking our local CS.
func (s *ClientStore) GetLvl2Key(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (drkey.Lvl2Key, error) {

	// is it in storage?
	k, err := s.db.GetLvl2Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl2Key{}, common.NewBasicError("Cannot retrieve key from DB", err)
	}
	// if not, ask our CS for it
	req := drkey_mgmt.NewLvl2ReqFromMeta(meta, valTime)
	csAddress := &snet.Addr{IA: s.ia, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	rep, err := s.msger.RequestDRKeyLvl2(ctx, &req, csAddress, messenger.NextId())
	if err != nil {
		return drkey.Lvl2Key{},
			common.NewBasicError("Error sending DRKey lvl2 request via messenger", err)
	}
	return rep.ToKey(meta), nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientStore) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now()))
	return int(i), err
}
