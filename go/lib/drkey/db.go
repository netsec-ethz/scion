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
	"io"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

// BaseDB defines basic interface
type BaseDB interface {
	io.Closer
	db.LimitSetter
}

// Lvl1DB is the drkey database interface for level 1.
type Lvl1DB interface {
	BaseDB
	GetLvl1Key(ctx context.Context, key Lvl1Meta, valTime uint32) (Lvl1Key, error)
	InsertLvl1Key(ctx context.Context, key Lvl1Key) error
	RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error)
	GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error)
	GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error)
}

// Lvl2DB is the drkey database interface for level 2.
type Lvl2DB interface {
	BaseDB
	GetLvl2Key(ctx context.Context, key Lvl2Meta, valTime uint32) (Lvl2Key, error)
	InsertLvl2Key(ctx context.Context, key Lvl2Key) error
	RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error)
}
