// Copyright 2025 ETH Zurich
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
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental/mock_experimental"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type remoteMapsRequestMatcher struct {
	expected *experimental.RemoteMapsRequest
}

func (r remoteMapsRequestMatcher) Matches(x interface{}) bool {
	xp, ok := x.(*experimental.RemoteMapsRequest)
	if !ok {
		return false
	}
	return xp.IsdAs == r.expected.IsdAs && bytes.Equal(xp.Digest, r.expected.Digest)
}
func (r remoteMapsRequestMatcher) String() string {
	return fmt.Sprintf("%v", r.expected)
}
func MatchesRemoteMapsRequest(expected *experimental.RemoteMapsRequest) gomock.Matcher {
	return remoteMapsRequestMatcher{expected}
}

func TestFetchFabridDetachedMaps(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_experimental.NewMockFABRIDIntraServiceClient(ctrl)

	server := &DaemonServer{}

	ctx := context.Background()

	// Create paths with detached hops
	oldPath1 := path.Path{
		Src: xtest.MustParseIA("1-ff00:0:110"),
		Dst: xtest.MustParseIA("1-ff00:0:113"),
		Meta: snet.PathMetadata{
			// Hops are : AS 110 (0-1) -> AS 111 (2-3) -> AS 113 (4-0)
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("1-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: false, Digest: []byte("firstDigest")},
				{Enabled: true, Detached: true, Digest: []byte("secondDigest")},
				{Enabled: true, Detached: true, Digest: []byte("thirdDigest")},
			},
		},
	}
	oldPath2 := path.Path{
		Src: xtest.MustParseIA("2-ff00:0:110"),
		Dst: xtest.MustParseIA("2-ff00:0:113"),
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("2-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("2-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: false, Digest: []byte("firstDigest")},
				{Enabled: true, Detached: false, Digest: []byte("secondDigest")},
				{Enabled: true, Detached: true, Digest: []byte("thirdDigest")},
			},
		},
	}

	paths := []snet.Path{
		oldPath1,
		oldPath2,
	}

	// We expect three fetches for the remote maps
	// Respond with a map that has no policies relevant to the current path
	mockClient.EXPECT().RemoteMaps(ctx, MatchesRemoteMapsRequest(
		&experimental.RemoteMapsRequest{IsdAs: uint64(xtest.MustParseIA("1-ff00:0:111")),
			Digest: []byte("secondDigest")})).Times(1).Return(
		&experimental.RemoteMapsResponse{Maps: &experimental.FABRIDDetachableMaps{
			SupportedIndicesMap: []*experimental.FABRIDIndexMapEntry{
				{
					IePair: &experimental.FABRIDIngressEgressPair{
						Ingress: &experimental.FABRIDConnectionPoint{
							Type: experimental.
								FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
							Interface: 3,
						},
						Egress: &experimental.FABRIDConnectionPoint{
							Type: experimental.FABRIDConnectionType_FABRID_CONNECTION_TYPE_WILDCARD,
						},
					},
					SupportedPolicyIndices: []uint32{2, 15},
				}},
			IndexIdentifierMap: map[uint32]*experimental.FABRIDPolicyIdentifier{
				2: {
					PolicyIsLocal:    false,
					PolicyIdentifier: 22,
				},
				8: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 1,
				},
				15: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 121,
				},
			},
		}}, nil)
	// Respond with a map that has policies relevant to the current path
	mockClient.EXPECT().RemoteMaps(ctx, MatchesRemoteMapsRequest(&experimental.
		RemoteMapsRequest{IsdAs: uint64(xtest.MustParseIA("1-ff00:0:113")),
		Digest: []byte("thirdDigest")})).Times(1).Return(
		&experimental.RemoteMapsResponse{Maps: &experimental.FABRIDDetachableMaps{
			SupportedIndicesMap: []*experimental.FABRIDIndexMapEntry{
				{
					IePair: &experimental.FABRIDIngressEgressPair{
						Ingress: &experimental.FABRIDConnectionPoint{
							Type: experimental.
								FABRIDConnectionType_FABRID_CONNECTION_TYPE_WILDCARD,
						},
						Egress: &experimental.FABRIDConnectionPoint{
							Type: experimental.
								FABRIDConnectionType_FABRID_CONNECTION_TYPE_WILDCARD,
						},
					},
					SupportedPolicyIndices: []uint32{2, 15},
				}},
			IndexIdentifierMap: map[uint32]*experimental.FABRIDPolicyIdentifier{
				2: {
					PolicyIsLocal:    false,
					PolicyIdentifier: 33,
				},
				8: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 2,
				},
				15: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 232,
				},
			},
		}}, nil)
	// Respond with a map that has policies relevant to the current path
	mockClient.EXPECT().RemoteMaps(ctx, MatchesRemoteMapsRequest(&experimental.
		RemoteMapsRequest{IsdAs: uint64(xtest.MustParseIA("2-ff00:0:113")),
		Digest: []byte("thirdDigest")})).Times(1).Return(
		&experimental.RemoteMapsResponse{Maps: &experimental.FABRIDDetachableMaps{
			SupportedIndicesMap: []*experimental.FABRIDIndexMapEntry{
				{
					IePair: &experimental.FABRIDIngressEgressPair{
						Ingress: &experimental.FABRIDConnectionPoint{
							Type: experimental.
								FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
							Interface: 4,
						},
						Egress: &experimental.FABRIDConnectionPoint{
							Type: experimental.
								FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
							Interface: 0,
						},
					},
					SupportedPolicyIndices: []uint32{4, 8},
				}},
			IndexIdentifierMap: map[uint32]*experimental.FABRIDPolicyIdentifier{
				4: {
					PolicyIsLocal:    false,
					PolicyIdentifier: 44,
				},
				8: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 3,
				},
				10: {
					PolicyIsLocal:    true,
					PolicyIdentifier: 343,
				},
			},
		}}, nil)

	// Call the function
	server.fetchFabridDetachedMaps(ctx, paths, mockClient)

	// Verify results: check whether the FABRID Info policies are updated to reflect the
	// information learned from the maps.
	for _, path := range paths {
		assert.Equal(t, 3, len(path.Metadata().FabridInfo),
			"Amount of FABRID Info fields has changed")
		//
		for _, fi := range path.Metadata().FabridInfo {
			assert.False(t, fi.Detached, "FABRID Info was not marked as attached")
			assert.True(t, fi.Enabled, "FABRID disabled for a FABRID enabled AS")
		}
	}
	// Ensure no modifications to the paths themselves have happened and they are still in the
	// same order
	assert.Equal(t, oldPath1.Source(), paths[0].Source())
	assert.Equal(t, oldPath1.Destination(), paths[0].Destination())
	assert.Equal(t, oldPath2.Source(), paths[1].Source())
	assert.Equal(t, oldPath2.Destination(), paths[1].Destination())

	// Ensure the policies are correctly updated:
	p0meta := paths[0].Metadata()
	p1meta := paths[1].Metadata()
	assert.Equal(t, len(p0meta.FabridInfo[0].Policies), 0)
	assert.Equal(t, len(p0meta.FabridInfo[1].Policies), 0)
	assert.Equal(t, len(p0meta.FabridInfo[2].Policies), 2)
	found1 := false
	found2 := false
	// Order is not defined
	for _, pol := range p0meta.FabridInfo[2].Policies {
		if pol.Identifier == 33 && pol.IsLocal == false {
			found1 = true
		}
		if pol.Identifier == 232 && pol.IsLocal == true {
			found2 = true
		}
	}
	assert.True(t, found1, "Policy 33 not found in path 0 hop 2")
	assert.True(t, found2, "Policy 232 not found in path 0 hop 2")

	assert.Equal(t, len(p1meta.FabridInfo[0].Policies), 0)
	assert.Equal(t, len(p1meta.FabridInfo[1].Policies), 0)
	assert.Equal(t, len(p1meta.FabridInfo[2].Policies), 2)
	found1 = false
	found2 = false
	// Order is not defined
	for _, pol := range p1meta.FabridInfo[2].Policies {
		if pol.Identifier == 3 && pol.IsLocal == true {
			found1 = true
		}
		if pol.Identifier == 44 && pol.IsLocal == false {
			found2 = true
		}
	}
	assert.True(t, found1, "Policy 3 not found in path 1 hop 2")
	assert.True(t, found2, "Policy 44 not found in path 1 hop 2")
}

func TestFetchFabridDetachedMapsEmptyResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_experimental.NewMockFABRIDIntraServiceClient(ctrl)

	server := &DaemonServer{}

	ctx := context.Background()

	detached := [][]bool{{false, true, true}, {false, false, true}}
	// Create paths with detached hops
	oldPath1 := path.Path{
		Src: xtest.MustParseIA("1-ff00:0:110"),
		Dst: xtest.MustParseIA("1-ff00:0:113"),
		Meta: snet.PathMetadata{
			// Hops are : AS 110 (0-1) -> AS 111 (2-3) -> AS 113 (4-0)
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("1-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: detached[0][0], Digest: []byte("firstDigest")},
				{Enabled: true, Detached: detached[0][1], Digest: []byte("secondDigest")},
				{Enabled: true, Detached: detached[0][2], Digest: []byte("thirdDigest")},
			},
		},
	}
	oldPath2 := path.Path{
		Src: xtest.MustParseIA("2-ff00:0:110"),
		Dst: xtest.MustParseIA("2-ff00:0:113"),
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("2-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("2-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: detached[1][0], Digest: []byte("firstDigest")},
				{Enabled: true, Detached: detached[1][1], Digest: []byte("secondDigest")},
				{Enabled: true, Detached: detached[1][2], Digest: []byte("thirdDigest")},
			},
		},
	}

	paths := []snet.Path{
		oldPath1,
		oldPath2,
	}

	// We expect three fetches for the remote maps. Respond to each with an empty map.
	mockClient.EXPECT().RemoteMaps(ctx, gomock.Any()).Times(3).Return(&experimental.
		RemoteMapsResponse{Maps: nil}, nil)

	// Call the function
	server.fetchFabridDetachedMaps(ctx, paths, mockClient)

	// Check whether the FABRID Info fields are unchanged
	for _, path := range paths {
		assert.Equal(t, 3, len(path.Metadata().FabridInfo),
			"Amount of FABRID Info fields has changed")
		for _, fi := range path.Metadata().FabridInfo {
			assert.True(t, fi.Enabled, "FABRID disabled for a FABRID enabled AS")
			//TODO(jvanbommel): desired behavior? leave unchanged or mark as no longer detached
			assert.False(t, fi.Detached, "FABRID info should not be marked as detached")
		}
	}
	// Ensure no modifications to the paths themselves have happened and they are still in the
	// same order
	assert.Equal(t, oldPath1.Source(), paths[0].Source())
	assert.Equal(t, oldPath1.Destination(), paths[0].Destination())
	assert.Equal(t, oldPath2.Source(), paths[1].Source())
	assert.Equal(t, oldPath2.Destination(), paths[1].Destination())
}

func TestFetchFabridDetachedMapsNoDetachedHops(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_experimental.NewMockFABRIDIntraServiceClient(ctrl)

	server := &DaemonServer{}

	ctx := context.Background()

	// Create paths with detached hops
	oldPath1 := path.Path{
		Src: xtest.MustParseIA("1-ff00:0:110"),
		Dst: xtest.MustParseIA("1-ff00:0:113"),
		Meta: snet.PathMetadata{
			// Hops are : AS 110 (0-1) -> AS 111 (2-3) -> AS 113 (4-0)
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("1-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: false, Digest: []byte("firstDigest")},
				{Enabled: true, Detached: false, Digest: []byte("secondDigest")},
				{Enabled: true, Detached: false, Digest: []byte("thirdDigest")},
			},
		},
	}
	oldPath2 := path.Path{
		Src: xtest.MustParseIA("2-ff00:0:110"),
		Dst: xtest.MustParseIA("2-ff00:0:113"),
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: xtest.MustParseIA("2-ff00:0:110"), ID: 1},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 2},
				{IA: xtest.MustParseIA("2-ff00:0:111"), ID: 3},
				{IA: xtest.MustParseIA("2-ff00:0:113"), ID: 4},
			},
			FabridInfo: []snet.FabridInfo{
				{Enabled: true, Detached: false, Digest: []byte("firstDigest")},
				{Enabled: true, Detached: false, Digest: []byte("secondDigest")},
				{Enabled: true, Detached: false, Digest: []byte("thirdDigest")},
			},
		},
	}

	paths := []snet.Path{
		oldPath1,
		oldPath2,
	}

	// Since there are no detached hops, we do not expect any calls to fetch maps.
	mockClient.EXPECT().RemoteMaps(ctx, gomock.Any()).Times(0)

	// Call the function
	server.fetchFabridDetachedMaps(ctx, paths, mockClient)

	// Check whether the FABRID Info policies are not updated
	for _, path := range paths {
		assert.Equal(t, 3, len(path.Metadata().FabridInfo),
			"Amount of FABRID Info fields has changed")
		//
		for _, fi := range path.Metadata().FabridInfo {
			assert.False(t, fi.Detached, "FABRID Info was not marked as attached")
			assert.True(t, fi.Enabled, "FABRID disabled for a FABRID enabled AS")
			assert.Equal(t, len(fi.Policies), 0)
		}
	}
	// Ensure no modifications to the paths themselves have happened and they are still in the
	// same order
	assert.Equal(t, paths[0], oldPath1)
	assert.Equal(t, paths[1], oldPath2)
}
func TestFindDetachedHopsNoFABRIDEnabled(t *testing.T) {
	meta := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:112"), ID: 2},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:109"), ID: 0},
		},
		FabridInfo: []snet.FabridInfo{},
	}
	detachedHops := findDetachedHops(meta)
	assert.Empty(t, detachedHops, "Expected no detached hops when FABRID is not enabled")
}

func TestFindDetachedHopsHopsMalformed(t *testing.T) {
	meta := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:112"), ID: 2},
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
		},
		FabridInfo: []snet.FabridInfo{
			{Enabled: true, Detached: false},
			{Enabled: true, Detached: false},
			{Enabled: true, Detached: true, Digest: []byte("lastHopDigest")},
		},
	}
	detachedHops := findDetachedHops(meta)
	assert.Empty(t, detachedHops,
		"Expected no detached hops when the amount of hops does not correspond to the amount of"+
			" entries in FABRID info")
}
func TestFindDetachedHopsAllDetached(t *testing.T) {
	meta := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
			{IA: xtest.MustParseIA("1-ff00:0:112"), ID: 4},
		},
		FabridInfo: []snet.FabridInfo{
			{Enabled: true, Detached: true, Digest: []byte("firstHopDigest")},
			{Enabled: true, Detached: true, Digest: []byte("middleHopDigest")},
			{Enabled: true, Detached: true, Digest: []byte("lastHopDigest")},
		},
	}
	detachedHops := findDetachedHops(meta)
	assert.Len(t, detachedHops, 3, "Expected three detached hops")

	expectedHops := []tempHopInfo{
		{IA: xtest.MustParseIA("1-ff00:0:110"), Digest: []byte("firstHopDigest"), fiIdx: 0,
			Ingress: 0, Egress: 1},
		{IA: xtest.MustParseIA("1-ff00:0:111"), Digest: []byte("middleHopDigest"), fiIdx: 1,
			Ingress: 2, Egress: 3},
		{IA: xtest.MustParseIA("1-ff00:0:112"), Digest: []byte("lastHopDigest"), fiIdx: 2,
			Ingress: 4, Egress: 0},
	}

	for i, expected := range expectedHops {
		assert.Equal(t, expected.IA, detachedHops[i].IA)
		assert.Equal(t, expected.Digest, detachedHops[i].Digest)
		assert.Equal(t, expected.fiIdx, detachedHops[i].fiIdx)
		assert.Equal(t, expected.Ingress, detachedHops[i].Ingress)
		assert.Equal(t, expected.Egress, detachedHops[i].Egress)
	}
}

func TestFindDetachedHopsFirstHopDetached(t *testing.T) {
	meta := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
			{IA: xtest.MustParseIA("1-ff00:0:112"), ID: 4},
		},
		FabridInfo: []snet.FabridInfo{
			{Enabled: true, Detached: true, Digest: []byte("firstHopDigest")},
			{Enabled: true, Detached: false},
			{Enabled: true, Detached: false},
		},
	}
	detachedHops := findDetachedHops(meta)
	assert.Len(t, detachedHops, 1, "Expected one detached hop")
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), detachedHops[0].IA)
	assert.Equal(t, []byte("firstHopDigest"), detachedHops[0].Digest)
	assert.Equal(t, 0, detachedHops[0].fiIdx)
	assert.Equal(t, uint16(0), detachedHops[0].Ingress)
	assert.Equal(t, uint16(1), detachedHops[0].Egress)
}
func TestFindDetachedHopsLastHopDetached(t *testing.T) {
	meta := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:110"), ID: 1},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 2},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: 3},
			{IA: xtest.MustParseIA("1-ff00:0:112"), ID: 4},
		},
		FabridInfo: []snet.FabridInfo{
			{Enabled: true, Detached: false},
			{Enabled: true, Detached: false},
			{Enabled: true, Detached: true, Digest: []byte("lastHopDigest")},
		},
	}
	detachedHops := findDetachedHops(meta)
	assert.Len(t, detachedHops, 1, "Expected one detached hop")
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:112"), detachedHops[0].IA)
	assert.Equal(t, []byte("lastHopDigest"), detachedHops[0].Digest)
	assert.Equal(t, 2, detachedHops[0].fiIdx)
	assert.Equal(t, uint16(4), detachedHops[0].Ingress)
	assert.Equal(t, uint16(0), detachedHops[0].Egress)
}
