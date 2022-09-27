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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ClientEngine manages secret values and lvl2 keys and provides them to end hosts.
type ClientEngine interface {
	GetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	GetHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	GetHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
	DeleteExpiredKeys(ctx context.Context) (int, error)
}

// NewClientEngineCleaner creates a Cleaner task that removes expired lvl2 keys.
func NewClientEngineCleaner(s ClientEngine) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredKeys(ctx)
	}, "drkey_client_store")
}

// clientEngine is the DRKey store used in the client side.
type clientEngine struct {
	ia      addr.IA
	db      drkey.Lvl2DB
	fetcher drkey.Fetcher
}

var _ ClientEngine = &clientEngine{}

// NewClientEngine constructs a new client store without assigned messenger.
func NewClientEngine(local addr.IA, db drkey.Lvl2DB, fetcher drkey.Fetcher) *clientEngine {
	return &clientEngine{
		ia:      local,
		db:      db,
		fetcher: fetcher,
	}
}

// GetASHostKey returns the ASHost key from the local DB or if not found, by asking our local CS.
func (s *clientEngine) GetASHostKey(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	// is it in storage?
	k, err := s.db.GetASHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.ASHostKey{}, serrors.WrapStr("looking up AS-HOST key in DB", err)
	}

	// if not, ask our CS for it
	remoteKey, err := s.fetcher.DRKeyGetASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("fetching AS-Host key from local CS", err)
	}
	if err = s.db.InsertASHostKey(ctx, remoteKey); err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("inserting AS-Host key in DB", err)
	}
	return remoteKey, nil
}

// GetHostASKey returns the HostAS key from the local DB or if not found, by asking our local CS.
func (s *clientEngine) GetHostASKey(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	// is it in storage?
	k, err := s.db.GetHostASKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostASKey{}, serrors.WrapStr("looking up Host-AS key in DB", err)
	}
	// if not, ask our CS for it

	remoteKey, err := s.fetcher.DRKeyGetHostASKey(ctx, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("fetching Host-AS key from local CS", err)
	}
	if err = s.db.InsertHostASKey(ctx, remoteKey); err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("inserting Host-AS key in DB", err)
	}
	return remoteKey, nil
}

// GetHostHostKey returns the HostHost key from the local DB or if not found,
// by asking our local CS.
func (s *clientEngine) GetHostHostKey(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	// is it in storage?
	k, err := s.db.GetHostHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostHostKey{}, serrors.WrapStr("looking up Host-Host key in DB", err)
	}
	// if not, ask our CS for it

	remoteKey, err := s.fetcher.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("fetching Host-Host key from local CS", err)
	}
	if err = s.db.InsertHostHostKey(ctx, remoteKey); err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("inserting Host-Host key in DB", err)
	}
	return remoteKey, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *clientEngine) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.db.DeleteExpiredLvl2Keys(ctx, time.Now())
	return int(i), err
}
