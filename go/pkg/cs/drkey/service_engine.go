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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Fetcher obtains a Lvl1 DRKey from a remote CS.
type Fetcher interface {
	FetchLvl1(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error)
}

// ServiceEngine maintain and provides secret values, lvl1 keys and prefetching information.
type ServiceEngine interface {
	// Storing SVs in the server allows for the server to still have access to
	// handed out secrets even after rebooting. It is not critical to the server
	// to derive secret values fast, so the lookup operation is acceptable.

	GetSecretValue(ctx context.Context, meta drkey.SVMeta) (drkey.SV, error)

	DeriveLvl1(meta drkey.Lvl1Meta) (drkey.Lvl1Key, error)
	DeriveASHost(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	DeriveHostAS(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	DeriveHostHost(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
	GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error)
	GetLvl1PrefetchInfo() []Lvl1PrefetchInfo

	DeleteExpiredKeys(ctx context.Context) (int, error)
}

// NewServiceEngineCleaner creates a Cleaner task that removes expired lvl1 keys.
func NewServiceEngineCleaner(s ServiceEngine) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredKeys(ctx)
	}, "drkey_serv_store")
}

// serviceEngine keeps track of the level 1 drkey keys. It is backed by a drkey.DB
type serviceEngine struct {
	secretBackend  *secretValueBackend
	LocalIA        addr.IA
	DB             drkey.Lvl1DB
	Fetcher        Fetcher
	prefetchKeeper Lvl1PrefetchListKeeper
}

var _ ServiceEngine = (*serviceEngine)(nil)

func NewServiceEngine(localIA addr.IA, svdb drkey.SecretValueDB, masterKey []byte,
	keyDur time.Duration, lvl1db drkey.Lvl1DB, fetcher Fetcher,
	listSize int) (*serviceEngine, error) {
	list, err := NewLvl1ARC(listSize)
	if err != nil {
		return nil, err
	}
	return &serviceEngine{
		secretBackend:  newSecretValueBackend(svdb, masterKey, keyDur),
		LocalIA:        localIA,
		DB:             lvl1db,
		Fetcher:        fetcher,
		prefetchKeeper: list,
	}, nil
}

// GetSecretValue returns a valid secret value for the provided metadata.
// It tries to retrieve the secret value from persistence, otherwise
// it creates a new one and stores it away.
func (s *serviceEngine) GetSecretValue(ctx context.Context,
	meta drkey.SVMeta) (drkey.SV, error) {
	return s.secretBackend.getSecretValue(ctx, meta)
}

// GetLvl1Key returns the level 1 drkey from the local DB or if not found, by asking any CS in
// the source AS of the key. It also updates the Lvl1Cache, if needed
func (s *serviceEngine) GetLvl1Key(ctx context.Context,
	meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	key, err := s.getLvl1Key(ctx, meta)
	if err == nil && ctx.Value(fromPrefetcher{}) == nil && meta.SrcIA != s.LocalIA {
		keyInfo := Lvl1PrefetchInfo{
			IA:    key.SrcIA,
			Proto: meta.ProtoId,
		}
		s.prefetchKeeper.Update(keyInfo)
	}
	return key, err
}

func (s *serviceEngine) getLvl1Key(ctx context.Context,
	meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	logger := log.FromCtx(ctx)

	if meta.SrcIA == s.LocalIA {
		return s.DeriveLvl1(meta)
	}

	if meta.DstIA != s.LocalIA {
		return drkey.Lvl1Key{},
			serrors.New("Neither srcIA nor dstIA matches localIA", "srcIA", meta.SrcIA,
				"dstIA", meta.DstIA, "localIA", s.LocalIA)
	}

	// look in the DB
	k, err := s.DB.GetLvl1Key(ctx, meta)
	if err == nil {
		logger.Debug("[DRKey Backend] L1 key found in storage")
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.Lvl1Key{}, serrors.WrapStr("retrieving key from DB", err)
	}

	// get it from another server
	remoteKey, err := s.Fetcher.FetchLvl1(ctx, meta)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining level 1 key from CS", err)
	}
	// keep it in our DB
	err = s.DB.InsertLvl1Key(ctx, remoteKey)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("storing obtained key in DB", err)
	}
	return remoteKey, nil
}

func (s *serviceEngine) obtainLvl1Key(ctx context.Context,
	meta drkey.Lvl2Meta) (drkey.Lvl1Key, error) {
	proto := meta.ProtoId
	if !proto.IsPredefined() {
		proto = drkey.Generic
	}
	lvl1Meta := drkey.Lvl1Meta{
		Validity: meta.Validity,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		ProtoId:  proto,
	}
	return s.getLvl1Key(ctx, lvl1Meta)

}

// DeleteExpiredKeys will remove any lvl1 expired keys.
func (s *serviceEngine) deleteExpiredLvl1Keys(ctx context.Context) (int, error) {
	i, err := s.DB.DeleteExpiredLvl1Keys(ctx, time.Now())
	return int(i), err
}

func (s *serviceEngine) DeleteExpiredKeys(ctx context.Context) (int, error) {
	lvl1Removed, err := s.deleteExpiredLvl1Keys(ctx)
	if err != nil {
		return int(lvl1Removed), err
	}
	svRemoved, err := s.secretBackend.deleteExpiredSV(ctx)
	return int(lvl1Removed + svRemoved), err
}

// GetCachedASes returns a list of ASes currently in the cache.
func (s *serviceEngine) GetLvl1PrefetchInfo() []Lvl1PrefetchInfo {
	return s.prefetchKeeper.GetLvl1InfoArray()
}

// DeriveLvl1 returns a Lvl1 key based on the presented information
func (s *serviceEngine) DeriveLvl1(meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	sv, err := s.GetSecretValue(context.Background(), drkey.SVMeta{
		ProtoId:  meta.ProtoId,
		Validity: meta.Validity,
	})
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("getting secret value", err)
	}
	key, err := deriveLvl1(meta, sv)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("deriving level 1 key", err)
	}
	return key, nil
}

func deriveLvl1(meta drkey.Lvl1Meta, sv drkey.SV) (drkey.Lvl1Key, error) {
	key, err := (&drkey.SpecificDeriver{}).DeriveLvl1(meta, sv.Key)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("computing lvl1 raw key", err)
	}
	return drkey.Lvl1Key{
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		ProtoId: sv.ProtoId,
		Key:     key,
	}, nil
}

func (s *serviceEngine) DeriveASHost(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	// input size for the current implementation will be at most 2*aes.Blocksize
	var key drkey.Key
	var err error

	lvl1Key, err := s.obtainLvl1Key(ctx, meta.Lvl2Meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("getting  lvl1 key", err)
	}

	if meta.ProtoId.IsPredefined() {
		key, err = (&drkey.SpecificDeriver{}).DeriveASHost(meta, lvl1Key.Key)
		if err != nil {
			return drkey.ASHostKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	} else {
		key, err = (&drkey.GenericDeriver{}).DeriveASHost(meta, lvl1Key.Key)
		if err != nil {
			return drkey.ASHostKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	}
	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1Key.Epoch,
		SrcIA:   lvl1Key.SrcIA,
		DstIA:   lvl1Key.DstIA,
		DstHost: meta.DstHost,
		Key:     key,
	}, nil
}
func (s *serviceEngine) DeriveHostAS(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {
	// input size for the current implementation will be at most 2*aes.Blocksize
	var key drkey.Key
	var err error

	lvl1Key, err := s.obtainLvl1Key(ctx, meta.Lvl2Meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("getting  lvl1 key", err)
	}

	if meta.ProtoId.IsPredefined() {
		key, err = (&drkey.SpecificDeriver{}).DeriveHostAS(meta, lvl1Key.Key)
		if err != nil {
			return drkey.HostASKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	} else {
		key, err = (&drkey.GenericDeriver{}).DeriveHostAS(meta, lvl1Key.Key)
		if err != nil {
			return drkey.HostASKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	}
	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1Key.Epoch,
		SrcIA:   lvl1Key.SrcIA,
		DstIA:   lvl1Key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     key,
	}, nil
}
func (s *serviceEngine) DeriveHostHost(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	hostASMeta := drkey.HostASMeta{
		Lvl2Meta: meta.Lvl2Meta,
		SrcHost:  meta.SrcHost,
	}
	// input size for the current implementation will be at most 2*aes.Blocksize
	var key drkey.Key
	var err error

	hostASKey, err := s.DeriveHostAS(ctx, hostASMeta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("computing intermediate Host-AS key", err)
	}

	if meta.ProtoId.IsPredefined() {
		key, err = (&drkey.SpecificDeriver{}).DeriveHostToHost(meta.DstHost, hostASKey.Key)
		if err != nil {
			return drkey.HostHostKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	} else {
		key, err = (&drkey.GenericDeriver{}).DeriveHostToHost(meta.DstHost, hostASKey.Key)
		if err != nil {
			return drkey.HostHostKey{}, serrors.WrapStr("parsing derivation input", err)
		}
	}
	return drkey.HostHostKey{
		ProtoId: hostASKey.ProtoId,
		Epoch:   hostASKey.Epoch,
		SrcIA:   hostASKey.SrcIA,
		DstIA:   hostASKey.DstIA,
		SrcHost: hostASKey.SrcHost,
		DstHost: meta.DstHost,
		Key:     key,
	}, nil
}
