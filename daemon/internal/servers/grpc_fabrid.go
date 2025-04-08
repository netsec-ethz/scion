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

package servers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	timestamppb "github.com/golang/protobuf/ptypes/timestamp"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	fabrid_utils "github.com/scionproto/scion/pkg/experimental/fabrid/graphutils"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

type tempHopInfo struct {
	IA      addr.IA
	Digest  []byte
	fiIdx   int
	Ingress uint16
	Egress  uint16
}

// fetchFabridDetachedMaps uses findDetachedHops to find the detached hops in a path, for a given
// list of paths. The detached map is then fetched with fetchMaps and the path in the list of paths
// is updated. Parameter client may be nil.
func (s *DaemonServer) fetchFabridDetachedMaps(ctx context.Context, paths []snet.Path,
	client experimental.FABRIDIntraServiceClient) {
	fetchedMaps := make(map[addr.IA]fabrid_utils.FabridMapEntry)
	// Check for each path whether they have hops that have a detached map
	for i := 0; i < len(paths); i++ {
		pMeta := paths[i].Metadata()
		hops := findDetachedHops(pMeta)
		if len(hops) == 0 {
			continue
		}
		// There are detached hops, which means we need to update the path's metadata,
		// create a copy.
		newPath := snetpath.Path{
			Src:           paths[i].Source(),
			Dst:           paths[i].Destination(),
			DataplanePath: paths[i].Dataplane(),
			NextHop:       paths[i].UnderlayNextHop(),
			Meta:          *paths[i].Metadata(),
		}
		// We need to fetch the detached hops, check if there is already a connection to the CS.
		if client == nil {
			conn, err := s.Dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
			if err != nil {
				log.FromCtx(ctx).Debug("Dialing CS failed", "err", err)
				continue
			}
			defer conn.Close()
			client = experimental.NewFABRIDIntraServiceClient(conn)
		}
		// Fetch the FABRID maps for this AS and update the metadata
		for _, h := range hops {
			// Only fetch if not previously fetched
			if _, exist := fetchedMaps[h.IA]; !exist {
				fetchedMaps[h.IA] = fetchMaps(ctx, h.IA, client, h.Digest)
			}
			// With the fetched map get an updated FABRID Info for this detached hop.
			newFi := *fabrid_utils.GetFabridInfoForIntfs(h.IA, h.Ingress, h.Egress, fetchedMaps,
				true)
			// Update the metadata
			newPath.Meta.FabridInfo[h.fiIdx] = newFi
		}
		// Update the path
		paths[i] = newPath
	}
}

// findDetachedHops finds the hops where the FABRID maps have been detached in a given list of
// paths.
func findDetachedHops(meta *snet.PathMetadata) []tempHopInfo {
	detachedHops := make([]tempHopInfo, 0)
	// If the source AS does not support FABRID, the FABRID Info array will be empty.
	if len(meta.FabridInfo) == 0 || len(meta.FabridInfo) != len(meta.Interfaces)/2+1 {
		log.Info("source AS does not support FABRID")
		return detachedHops
	}
	if meta.FabridInfo[0].Enabled && meta.FabridInfo[0].Detached {
		detachedHops = append(detachedHops, tempHopInfo{
			IA:      meta.Interfaces[0].IA,
			Digest:  meta.FabridInfo[0].Digest,
			fiIdx:   0,
			Ingress: 0,
			Egress:  uint16(meta.Interfaces[0].ID),
		})
	}
	for i := 1; i < len(meta.Interfaces)-1; i += 2 {
		if meta.FabridInfo[(i+1)/2].Enabled &&
			meta.FabridInfo[(i+1)/2].Detached {
			detachedHops = append(detachedHops, tempHopInfo{
				IA:      meta.Interfaces[i].IA,
				Digest:  meta.FabridInfo[(i+1)/2].Digest,
				fiIdx:   (i + 1) / 2,
				Ingress: uint16(meta.Interfaces[i].ID),
				Egress:  uint16(meta.Interfaces[i+1].ID),
			})
		}
	}
	if meta.FabridInfo[len(meta.Interfaces)/2].Enabled &&
		meta.FabridInfo[len(meta.Interfaces)/2].Detached {
		detachedHops = append(detachedHops, tempHopInfo{
			IA:      meta.Interfaces[len(meta.Interfaces)-1].IA,
			Digest:  meta.FabridInfo[len(meta.Interfaces)/2].Digest,
			fiIdx:   len(meta.Interfaces) / 2,
			Ingress: uint16(meta.Interfaces[len(meta.Interfaces)-1].ID),
			Egress:  0,
		})
	}
	return detachedHops
}

// fetchMaps retrieves FABRID maps from the Control Service for a given ISD-AS.
// It uses the provided client to communicate with the Control Service and returns a FabridMapEntry
// to be used directly in the combinator.
func fetchMaps(ctx context.Context, ia addr.IA, client experimental.FABRIDIntraServiceClient,
	digest []byte) fabrid_utils.FabridMapEntry {
	maps, err := client.RemoteMaps(ctx, &experimental.RemoteMapsRequest{
		Digest: digest,
		IsdAs:  uint64(ia),
	})
	if err != nil || maps.Maps == nil {
		log.FromCtx(ctx).Debug("Retrieving remote map from CS failed", "err", err, "ia",
			ia)
		return fabrid_utils.FabridMapEntry{}
	}

	detached := fabrid_ext.Detached{
		SupportedIndicesMap: fabrid_ext.SupportedIndicesMapFromPB(maps.Maps.SupportedIndicesMap),
		IndexIdentiferMap:   fabrid_ext.IndexIdentifierMapFromPB(maps.Maps.IndexIdentifierMap),
	}
	return fabrid_utils.FabridMapEntry{
		Map:    &detached,
		Ts:     time.Now(),
		Digest: []byte{}, // leave empty, it can be calculated using detached.Hash()
	}
}

func fabridPolicyToPB(fp *fabrid.Policy) *sdpb.FabridPolicy {
	return &sdpb.FabridPolicy{
		PolicyIdentifier: &experimental.FABRIDPolicyIdentifier{
			PolicyIsLocal:    fp.IsLocal,
			PolicyIdentifier: fp.Identifier,
		},
		PolicyIndex: uint32(fp.Index),
	}
}

func fabridInfoToPB(fi *snet.FabridInfo) *sdpb.FabridInfo {
	pbPolicies := make([]*sdpb.FabridPolicy, len(fi.Policies))
	for i, fp := range fi.Policies {
		pbPolicies[i] = fabridPolicyToPB(fp)
	}
	return &sdpb.FabridInfo{
		Enabled:  fi.Enabled,
		Digest:   fi.Digest,
		Policies: pbPolicies,
		Detached: fi.Detached,
	}
}

func (s *DaemonServer) FabridKeys(ctx context.Context, req *sdpb.FabridKeysRequest,
) (*sdpb.FabridKeysResponse, error) {
	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	pathASes := make([]addr.IA, 0, len(req.PathAses))
	for _, as := range req.PathAses {
		pathASes = append(pathASes, addr.IA(as))
	}
	resp, err := s.DRKeyClient.FabridKeys(ctx, drkey.FabridKeysMeta{
		SrcAS:    s.DRKeyClient.IA,
		SrcHost:  req.SrcHost,
		DstHost:  req.DstHost,
		PathASes: pathASes,
		DstAS:    addr.IA(req.DstAs),
	})
	if err != nil {
		return nil, serrors.WrapStr("getting fabrid keys from client store", err)
	}
	fabridKeys := make([]*sdpb.FabridKeyResponse, 0, len(resp.ASHostKeys))
	for i := range resp.ASHostKeys {
		key := resp.ASHostKeys[i]
		fabridKeys = append(fabridKeys, &sdpb.FabridKeyResponse{
			EpochBegin: &timestamppb.Timestamp{Seconds: key.Epoch.NotBefore.Unix()},
			EpochEnd:   &timestamppb.Timestamp{Seconds: key.Epoch.NotAfter.Unix()},
			Key:        key.Key[:],
		})
	}

	var hostHostKey *sdpb.FabridKeyResponse = nil
	if req.DstHost != nil {
		hostHostKey = &sdpb.FabridKeyResponse{
			EpochBegin: &timestamppb.Timestamp{Seconds: resp.PathKey.Epoch.NotBefore.Unix()},
			EpochEnd:   &timestamppb.Timestamp{Seconds: resp.PathKey.Epoch.NotAfter.Unix()},
			Key:        resp.PathKey.Key[:],
		}
	}
	return &sdpb.FabridKeysResponse{
		AsHostKeys:  fabridKeys,
		HostHostKey: hostHostKey,
	}, nil
}

func (s *DaemonServer) PolicyDescription(ctx context.Context,
	request *sdpb.PolicyDescriptionRequest) (
	*sdpb.PolicyDescriptionResponse, error) {

	var description string
	if request.IsLocal {
		conn, err := s.Dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
		if err != nil {
			log.FromCtx(ctx).Debug("Dialing CS failed", "err", err)
		}
		defer conn.Close()
		client := experimental.NewFABRIDIntraServiceClient(conn)
		response, err := client.RemotePolicyDescription(ctx,
			&experimental.RemotePolicyDescriptionRequest{
				PolicyIdentifier: request.PolicyIdentifier,
				IsdAs:            request.IsdAs,
			})
		if err != nil {
			return &sdpb.PolicyDescriptionResponse{}, err
		}
		description = response.Description
	} else {
		globalPolicyURL := fmt.Sprintf("%s/%d.json", s.FabridGlobalPolicyStore,
			request.PolicyIdentifier)

		// Fetch the global policy from the URL
		policy, err := FetchGlobalPolicy(globalPolicyURL)
		if err != nil {
			return nil, serrors.WrapStr("fetching global policy", err)
		}
		// Grab the description from the fetched policy
		if policy != nil {
			description = policy.Description
		}
	}
	return &sdpb.PolicyDescriptionResponse{Description: description}, nil
}

// GlobalPolicy holds a mapping of uint32 identifiers to their string descriptions
type GlobalPolicy struct {
	Description string `json:"description"`
}

// FetchGlobalPolicy fetches and parses the global policy from the given URL
func FetchGlobalPolicy(url string) (*GlobalPolicy, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, serrors.WrapStr("failed to fetch global policy", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, serrors.New("global policy not found")
		}
		return nil, serrors.New("failed to fetch global policy", "StatusCode", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, serrors.WrapStr("failed to read response body", err)
	}

	// Unmarshal the JSON data into a map
	var policy GlobalPolicy
	if err = json.Unmarshal(body, &policy); err != nil {
		return nil, serrors.WrapStr("failed to unmarshal policy JSON", err)
	}

	return &policy, nil
}
