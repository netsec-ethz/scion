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

package daemon

import (
	"context"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
)

func fabridInfoFromPB(fi *sdpb.FabridInfo) snet.FabridInfo {
	pbPolicies := make([]*fabrid.Policy, len(fi.Policies))
	for i, fp := range fi.Policies {
		pbPolicies[i] = &fabrid.Policy{
			IsLocal:    fp.PolicyIdentifier.PolicyIsLocal,
			Identifier: fp.PolicyIdentifier.PolicyIdentifier,
			Index:      fabrid.PolicyID(fp.PolicyIndex),
		}
	}
	return snet.FabridInfo{
		Enabled:  fi.Enabled,
		Policies: pbPolicies,
		Digest:   fi.Digest,
		Detached: fi.Detached,
	}
}

// Returns all the ASHost DRKeys for the ASes inside the meta.PathAS
func (c grpcConn) FabridKeys(ctx context.Context, meta drkey.FabridKeysMeta,
) (drkey.FabridKeysResponse, error) {

	client := sdpb.NewDaemonServiceClient((c.conn))
	pathASes := make([]uint64, 0, len(meta.PathASes))
	for i := 0; i < len(meta.PathASes); i++ {
		pathASes = append(pathASes, uint64(meta.PathASes[i]))
	}
	resp, err := client.FabridKeys(ctx, &sdpb.FabridKeysRequest{
		SrcHost:  meta.SrcHost,
		PathAses: pathASes,
		DstAs:    uint64(meta.DstAS),
		DstHost:  meta.DstHost,
	})
	if err != nil {
		return drkey.FabridKeysResponse{}, err
	}
	asHostKeys := make([]drkey.FabridKey, 0, len(resp.AsHostKeys))
	for i, key := range resp.AsHostKeys {
		epoch := drkey.Epoch{
			Validity: cppki.Validity{
				NotBefore: key.EpochBegin.AsTime(),
				NotAfter:  key.EpochEnd.AsTime(),
			},
		}
		asHostKeys = append(asHostKeys, drkey.FabridKey{
			Epoch: epoch,
			AS:    meta.PathASes[i],
			Key:   drkey.Key(key.Key),
		})
	}
	var hostHostKey drkey.FabridKey = drkey.FabridKey{}
	if resp.HostHostKey != nil {
		hostHostKey = drkey.FabridKey{
			Epoch: drkey.Epoch{
				Validity: cppki.Validity{
					NotBefore: resp.HostHostKey.EpochBegin.AsTime(),
					NotAfter:  resp.HostHostKey.EpochEnd.AsTime(),
				},
			},
			AS:  meta.DstAS,
			Key: drkey.Key(resp.HostHostKey.Key),
		}
	}
	return drkey.FabridKeysResponse{
		ASHostKeys: asHostKeys,
		PathKey:    hostHostKey,
	}, nil
}
