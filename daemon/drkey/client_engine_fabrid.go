// Copyright 2024 ETH Zurich
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

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// For all ASHost Keys and for the HostHost Key, it checks whether the keys are in the database.
// If this is the case, those keys are returned. If not, the keys are requested from CS.
func (e *ClientEngine) FabridKeys(ctx context.Context, meta drkey.FabridKeysMeta,
) (drkey.FabridKeysResponse, error) {
	now := time.Now()
	hostHostKey := drkey.FabridKey{}
	if meta.DstHost != nil && len(meta.PathASes) > 0 {
		key, err := e.GetHostHostKey(ctx, drkey.HostHostMeta{
			ProtoId:  drkey.FABRID,
			Validity: now,
			SrcIA:    meta.DstAS,
			SrcHost:  *meta.DstHost,
			DstIA:    meta.SrcAS,
			DstHost:  meta.SrcHost,
		})
		if err != nil {
			return drkey.FabridKeysResponse{}, serrors.WrapStr("prepare FABRID host-host key", err)
		}
		hostHostKey = drkey.FabridKey{
			Epoch: key.Epoch,
			AS:    meta.DstAS,
			Key:   key.Key,
		}
	}
	asHostKeys := make([]drkey.FabridKey, 0, len(meta.PathASes))
	for _, as := range meta.PathASes {
		key, err := e.GetASHostKey(ctx, drkey.ASHostMeta{
			ProtoId:  drkey.FABRID,
			Validity: now,
			SrcIA:    as,
			DstIA:    meta.SrcAS,
			DstHost:  meta.SrcHost,
		})
		if err != nil {
			return drkey.FabridKeysResponse{}, serrors.WrapStr("prepare FABRID AS-host key", err)
		}
		asHostKeys = append(asHostKeys, drkey.FabridKey{
			Epoch: key.Epoch,
			AS:    as,
			Key:   key.Key,
		})
	}

	return drkey.FabridKeysResponse{
		ASHostKeys: asHostKeys,
		PathKey:    hostHostKey,
	}, nil
}
