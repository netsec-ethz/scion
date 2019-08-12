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
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
)

// SecretValueFactory has the functionality to store secret values.
type SecretValueFactory interface {
	// GetKeyDuration returns the duration set to secret values when first created.
	GetKeyDuration() time.Duration
	// GetSecretValue returns the secret value given a point in time. The mapping returns the same
	// secret value for time points within the same time window [t/Duration, t/Duration +1) .
	GetSecretValue(time.Time) (drkey.SV, error)
}

// ServiceStore is the level 1 drkey store, used by the CS.
// It will keep a cache of those keys that were retrieved from the network.
// It automatically removes expired keys.
type ServiceStore interface {
	GetLvl1Key(ctx context.Context, meta drkey.Lvl1Meta, valTime time.Time) (drkey.Lvl1Key, error)
	// GetAllLvl1SrcASes(ctx context.Context) ([]addr.IA, error)
	// GetValidLvl1SrcASes(ctx context.Context) ([]addr.IA, error)
	DeleteExpiredKeys(ctx context.Context) (int, error)
	NewLvl1ReqHandler() infra.Handler
	NewLvl2ReqHandler(registry *protocol.Registry) infra.Handler
	SetMessenger(msger infra.Messenger)
	MsgVerificationFactory
}

type MsgVerificationFactory interface {
	// TODO(juagargi)
	// NewSigner(key common.RawBytes, meta SignerMeta) (Signer, error)
	// NewVerifier() Verifier
}

// NewServiceStoreCleaner creates a Cleaner task that removes expired level 1 drkeys.
func NewServiceStoreCleaner(s ServiceStore) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredKeys(ctx)
	}, "lvl1Keys")
}
