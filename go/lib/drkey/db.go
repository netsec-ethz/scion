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
)

// DB is the DRKey database interface for leve 1 and 2 keys
type DB interface {
	io.Closer
	GetDRKeyLvl1(ctx context.Context, key Lvl1Meta, valTime uint32) (Lvl1Key, error)
	InsertDRKeyLvl1(ctx context.Context, key Lvl1Key) (int64, error)
	RemoveOutdatedDRKeyLvl1(ctx context.Context, cutoff uint32) (int64, error)
	GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error)
	GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error)
	GetDRKeyLvl2(ctx context.Context, key Lvl2Meta, valTime uint32) (Lvl2Key, error)
	InsertDRKeyLvl2(ctx context.Context, key Lvl2Key) (int64, error)
	RemoveOutdatedDRKeyLvl2(ctx context.Context, cutoff uint32) (int64, error)
}
