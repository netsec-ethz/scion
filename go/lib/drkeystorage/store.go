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
	GetKeyDuration() time.Duration
	SetKeyDuration(duration time.Duration) error
	GetMasterKey() common.RawBytes
	SetMasterKey(key common.RawBytes) error
	SecretValue(time.Time) (*drkey.SV, error)
}

// Lvl1Store has all the functions dealing with storage/retrieval of level 1 DRKeys.
type Lvl1Store interface {
	GetDRKeyLvl1(ctx context.Context, key drkey.Lvl1Meta, valTime uint32) (drkey.Lvl1Key, error)
	InsertDRKeyLvl1(ctx context.Context, key drkey.Lvl1Key) (int64, error)
	RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error)
	GetL1SrcASes(ctx context.Context) ([]addr.IA, error)
	GetValidL1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error)
}

// Lvl2Store has all the functions dealing with storage/retrieval of level 2 DRKeys.
type Lvl2Store interface {
	GetDRKeyLvl2(ctx context.Context, key drkey.Lvl2Meta, valTime uint32) (drkey.Lvl2Key, error)
	InsertDRKeyLvl2(ctx context.Context, key drkey.Lvl2Key) (int64, error)
	RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error)
}

// Store has access to SV, L1 and L2 DRKeys
type Store interface {
	SecretValueStore
	Lvl1Store
	Lvl2Store
}
