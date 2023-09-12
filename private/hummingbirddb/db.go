// Copyright 2023 ETH Zurich
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

package hummingbirddb

import (
	"context"
	"database/sql"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
)

type DB interface {
	ReadWrite
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
}

type Read interface {
	GetFlyovers(ctx context.Context, IAs []addr.IA) ([]*hummingbird.Flyover, error)
}
type Write interface {
	StoreFlyovers(ctx context.Context, flyovers []*hummingbird.Flyover) error
	DeleteExpiredFlyovers(ctx context.Context) (int, error)
}

type ReadWrite interface {
	Read
	Write
}

type Transaction interface {
	ReadWrite
	Commit() error
	Rollback() error
}
