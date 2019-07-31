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

package drkeystorage

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
)

// SecretValueStore has the functionality to store secret values.
type SecretValueStore interface {
	// GetKeyDuration returns the duration set to secret values when first created.
	GetKeyDuration() time.Duration
	// SetKeyDuration establishes the duration of the secret value epochs when created.
	SetKeyDuration(duration time.Duration) error
	// GetMasterKey returns the master key set in this secret value store.
	GetMasterKey() common.RawBytes
	// SetMasterKey establishes the master key used to derive secret values in this store.
	SetMasterKey(key common.RawBytes) error
	// SecretValue returns the secret value given a point in time. The mapping returns the same
	// secret value for time points within the same time window [t/Duration, t/Duration +1) .
	SecretValue(time.Time) (*drkey.SV, error)
}

// Lvl1Store has all the functions dealing with storage/retrieval of level 1 DRKeys.
type Lvl1Store interface {
	GetLvl1Key(ctx context.Context, key drkey.Lvl1Meta, valTime uint32) (drkey.Lvl1Key, error)
	InsertLvl1Key(ctx context.Context, key drkey.Lvl1Key) error
	RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error)
	GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error)
	GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error)
}

// Lvl2Store has all the functions dealing with storage/retrieval of level 2 DRKeys.
type Lvl2Store interface {
	GetLvl2Key(ctx context.Context, key drkey.Lvl2Meta, valTime uint32) (drkey.Lvl2Key, error)
	InsertLvl2Key(ctx context.Context, key drkey.Lvl2Key) error
	RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error)
}

// Store has access to SV, level 1 and 2 DRKeys
type Store interface {
	SecretValueStore
	Lvl1Store
	Lvl2Store
}
