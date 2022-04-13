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
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SecretValueStore keeps the current and next secret values and removes the expired ones.
type secretValueBackend struct {
	DB          drkey.SecretValueDB
	masterKey   []byte
	keyDuration time.Duration
}

// NewSecretValueStore creates a new SecretValueStore and initializes the cleaner.
func newSecretValueBackend(db drkey.SecretValueDB, masterKey []byte,
	keyDuration time.Duration) *secretValueBackend {
	return &secretValueBackend{
		DB:          db,
		masterKey:   masterKey,
		keyDuration: keyDuration,
	}
}

// DeleteExpiredSV deletes any expired secret value
func (s *secretValueBackend) deleteExpiredSV(ctx context.Context) (int, error) {
	i, err := s.DB.DeleteExpiredSV(ctx, time.Now())
	return int(i), err
}

// GetSecretValue returns a valid secret value for the provided metadata.
// It tries to retrieve the secret value from persistence, otherwise
// it creates a new one and stores it away.
func (s *secretValueBackend) getSecretValue(ctx context.Context,
	meta drkey.SVMeta) (drkey.SV, error) {
	duration := int64(s.keyDuration / time.Second) // duration in seconds
	k, err := s.DB.GetSV(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.SV{}, serrors.WrapStr("retrieving SV from DB", err)
	}

	idx := meta.Validity.Unix() / duration
	begin := uint32(idx * duration)
	end := begin + uint32(duration)
	epoch := drkey.NewEpoch(begin, end)
	sv, err := drkey.DeriveSV(meta.ProtoId, epoch, s.masterKey)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("deriving DRKey secret value", err)
	}
	err = s.DB.InsertSV(ctx, sv)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("inserting SV in persistence", err)
	}
	return sv, nil
}
