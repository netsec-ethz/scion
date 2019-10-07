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

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
)

// SecretValueFactory has the functionality to store secret values.
type SecretValueFactory interface {
	GetSecretValue(time.Time) (drkey.SV, error)
}

type BaseStore interface {
	DeleteExpiredKeys(ctx context.Context) (int, error)
	// TODO(juagargi) the drkey store is unnecessary to create a messenger. Remove SetMessenger
	// and make the prior presence of a messenger mandatory for the creation of any drkey store.
	SetMessenger(msger infra.Messenger)
}

// ServiceStore is the level 1 drkey store, used by the CS.
// It will keep a cache of those keys that were retrieved from the network.
// It automatically removes expired keys.
type ServiceStore interface {
	BaseStore
	GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta, valTime time.Time) (drkey.Lvl1Key, error)
	NewLvl1ReqHandler() infra.Handler
	NewLvl2ReqHandler() infra.Handler
	MsgVerificationFactory
}

// ClientStore is the level 2 drkey store, used by sciond.
// It can get level 2 keys from its backes storage, or by
// asking a remote CS.
type ClientStore interface {
	BaseStore
	GetLvl2Key(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (drkey.Lvl2Key, error)
}

type MsgVerificationFactory interface {
	// TODO(juagargi)
	// NewSigner(key common.RawBytes, meta SignerMeta) (Signer, error)
	// NewVerifier() Verifier
}

// NewServiceStoreCleaner creates a Cleaner task that removes expired level 1 drkeys.
func NewStoreCleaner(s BaseStore) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredKeys(ctx)
	}, "lvl1Keys")
}
