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

// NoDRKey implements a valid but disabled DRKey store. We use it when DRKey is disabled.
type NoDRKey struct {
}

// NewDisabledStore returns a valid, but disabled drkey store.
func NewDisabledStore() Store {
	return NoDRKey{}
}

// GetKeyDuration not implemented.
func (NoDRKey) GetKeyDuration() time.Duration {
	panic("Not implemented")
}

// SetKeyDuration does not set it, but it returns no error.
func (NoDRKey) SetKeyDuration(duration time.Duration) error {
	return nil
}

// GetMasterKey not implemented.
func (NoDRKey) GetMasterKey() common.RawBytes {
	panic("Not implemented")
}

// SetMasterKey does not set it, but returns no error.
func (NoDRKey) SetMasterKey(key common.RawBytes) error {
	return nil
}

// SecretValue not implemented.
func (NoDRKey) SecretValue(time.Time) (*drkey.SV, error) {
	panic("Not implemented")
}

// GetLvl1Key not implemented.
func (NoDRKey) GetLvl1Key(ctx context.Context, key drkey.Lvl1Meta, valTime uint32) (drkey.Lvl1Key, error) {
	panic("Not implemented")
}

// InsertLvl1Key not implemented.
func (NoDRKey) InsertLvl1Key(ctx context.Context, key drkey.Lvl1Key) error {
	panic("Not implemented")
}

// RemoveOutdatedLvl1Keys not implemented.
func (NoDRKey) RemoveOutdatedLvl1Keys(ctx context.Context, cutoff uint32) (int64, error) {
	panic("Not implemented")
}

// GetLvl1SrcASes not implemented.
func (NoDRKey) GetLvl1SrcASes(ctx context.Context) ([]addr.IA, error) {
	panic("Not implemented")
}

// GetValidLvl1SrcASes not implemented.
func (NoDRKey) GetValidLvl1SrcASes(ctx context.Context, valTime uint32) ([]addr.IA, error) {
	panic("Not implemented")
}

// GetLvl2Key not implemented.
func (NoDRKey) GetLvl2Key(ctx context.Context, key drkey.Lvl2Meta, valTime uint32) (drkey.Lvl2Key, error) {
	panic("Not implemented")
}

// InsertLvl2Key not implemented.
func (NoDRKey) InsertLvl2Key(ctx context.Context, key drkey.Lvl2Key) error {
	panic("Not implemented")
}

// RemoveOutdatedLvl2Keys not implemented.
func (NoDRKey) RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error) {
	panic("Not implemented")
}
