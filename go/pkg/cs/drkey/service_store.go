// Copyright 2020 ETH Zurich
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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Fetcher obtains a Lvl1 DRKey from a remote CS.
type Fetcher interface {
	GetLvl1FromOtherCS(ctx context.Context,
		srcIA, dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error)
}

// ServiceStore keeps track of the level 1 drkey keys. It is backed by a drkey.DB .
type ServiceStore struct {
	LocalIA      addr.IA
	DB           drkey.Lvl1DB
	SecretValues drkeystorage.SecretValueFactory
	Fetcher      Fetcher
}

var _ drkeystorage.ServiceStore = (*ServiceStore)(nil)

// GetLvl1Key returns the level 1 drkey from the local DB or if not found, by asking any CS in
// the source AS of the key.
func (s *ServiceStore) GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta,
	valTime time.Time) (drkey.Lvl1Key, error) {
	logger := log.FromCtx(ctx)

	if meta.SrcIA == s.LocalIA {
		return s.DeriveLvl1(meta.DstIA, valTime)
	}
	// look in the DB
	k, err := s.DB.GetLvl1Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		logger.Debug("[DRKey ServiceStore] L1 key found in storage")
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl1Key{}, serrors.WrapStr("retrieving key from DB", err)
	}
	// get it from another server
	k, err = s.Fetcher.GetLvl1FromOtherCS(ctx, meta.SrcIA, meta.DstIA, valTime)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from CS", err)
	}
	// keep it in our DB
	err = s.DB.InsertLvl1Key(ctx, k)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("storing obtained key in DB", err)
	}
	return k, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ServiceStore) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.DB.RemoveOutdatedLvl1Keys(ctx, util.TimeToSecs(time.Now()))
	return int(i), err
}

// KnownASes returns a list with distinct AS seen as sources in level 1 DRKeys.
func (s *ServiceStore) KnownASes(ctx context.Context) ([]addr.IA, error) {
	return s.DB.GetLvl1SrcASes(ctx)
}

// DeriveLvl1 returns a Lvl1 DRKey based on present information
func (s *ServiceStore) DeriveLvl1(dstIA addr.IA, valTime time.Time) (drkey.Lvl1Key, error) {
	sv, err := s.SecretValues.GetSecretValue(valTime)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("getting secret value", err)
	}
	meta := drkey.Lvl1Meta{
		Epoch: sv.Epoch,
		SrcIA: s.LocalIA,
		DstIA: dstIA,
	}
	key, err := protocol.DeriveLvl1(meta, sv)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("deriving level 1 key", err)
	}
	return key, nil
}
