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

package grpc_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/fabrid"
	"github.com/scionproto/scion/control/fabrid/grpc"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
)

func TestFetchRemotePolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Metadata().AnyTimes().Return(&snet.PathMetadata{
		Interfaces: []snet.PathInterface{},
	})
	path.EXPECT().Dataplane().AnyTimes().Return(nil)
	path.EXPECT().UnderlayNextHop().AnyTimes().Return(&net.UDPAddr{})

	router := mock_snet.NewMockRouter(ctrl)
	router.EXPECT().AllRoutes(gomock.Any(), gomock.Any()).AnyTimes().Return([]snet.Path{path}, nil)
	tests := map[string]struct {
		IdentifierDescriptions map[uint32]string
		RequestedPolicy        uint32
		Assert                 assert.ErrorAssertionFunc
		PostCheck              func(t *testing.T,
			response *experimental.RemotePolicyDescriptionResponse)
	}{
		"existing": {
			IdentifierDescriptions: map[uint32]string{
				33: "Test Policy",
				45: "Second Test Policy",
			},
			RequestedPolicy: 33,
			Assert:          assert.NoError,
			PostCheck: func(t *testing.T, response *experimental.RemotePolicyDescriptionResponse) {
				require.Equal(t, response.Description, "Test Policy")
			},
		},
		"nonexistent": {
			IdentifierDescriptions: map[uint32]string{
				33: "Test Policy",
				45: "Second Test Policy",
			},
			RequestedPolicy: 55,
			Assert:          assert.Error,
			PostCheck: func(t *testing.T,
				response *experimental.RemotePolicyDescriptionResponse) {
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := xtest.NewGRPCService()
			experimental.RegisterFABRIDInterServiceServer(server.Server(), grpc.Server{
				FabridManager: &fabrid.FabridManager{
					IdentifierDescriptionMap: tc.IdentifierDescriptions,
				},
				Fetcher: &grpc.BasicFabridControlPlaneFetcher{},
			})
			server.Start(t)

			fetcher := grpc.BasicFabridControlPlaneFetcher{
				Dialer:     server,
				Router:     router,
				MaxRetries: 1,
			}

			policy, err := fetcher.GetRemotePolicy(context.Background(),
				xtest.MustParseIA("1-ff00:0:111"), tc.RequestedPolicy)
			tc.Assert(t, err)
			tc.PostCheck(t, policy)
		})
	}
}

func TestFetchRemoteMap(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Metadata().AnyTimes().Return(&snet.PathMetadata{
		Interfaces: []snet.PathInterface{},
	})
	path.EXPECT().Dataplane().AnyTimes().Return(nil)
	path.EXPECT().UnderlayNextHop().AnyTimes().Return(&net.UDPAddr{})

	router := mock_snet.NewMockRouter(ctrl)
	router.EXPECT().AllRoutes(gomock.Any(), gomock.Any()).AnyTimes().Return([]snet.Path{path}, nil)
	maps := fabrid_ext.Detached{
		SupportedIndicesMap: fabrid_ext.SupportedIndicesMap{
			fabrid_ext.ConnectionPair{
				Ingress: fabrid_ext.ConnectionPoint{
					Type:   fabrid_ext.IPv4Range,
					IP:     "192.168.2.0",
					Prefix: 24,
				},
				Egress: fabrid_ext.ConnectionPoint{
					Type:        fabrid_ext.Interface,
					InterfaceId: 5,
				},
			}: []uint8{2, 8, 15}},
		IndexIdentiferMap: fabrid_ext.IndexIdentifierMap{
			2: &fabrid_ext.PolicyIdentifier{
				IsLocal:    false,
				Identifier: 22,
			},
			8: &fabrid_ext.PolicyIdentifier{
				IsLocal:    true,
				Identifier: 1,
			},
			15: &fabrid_ext.PolicyIdentifier{
				IsLocal:    false,
				Identifier: 50,
			},
		},
	}
	t.Run("fabrid manager returns maps", func(t *testing.T) {
		server := xtest.NewGRPCService()
		experimental.RegisterFABRIDInterServiceServer(server.Server(), grpc.Server{
			FabridManager: &fabrid.FabridManager{
				SupportedIndicesMap: maps.SupportedIndicesMap,
				IndexIdentifierMap:  maps.IndexIdentiferMap,
			},
			Fetcher: &grpc.BasicFabridControlPlaneFetcher{},
		})
		server.Start(t)

		fetcher := grpc.BasicFabridControlPlaneFetcher{
			Dialer:     server,
			Router:     router,
			MaxRetries: 1,
		}

		fetchedMaps, err := fetcher.GetRemoteMaps(context.Background(),
			xtest.MustParseIA("1-ff00:0:111"))
		assert.NoError(t, err)
		require.Equal(t, fetchedMaps.Maps.SupportedIndicesMap,
			fabrid_ext.SupportedIndicesMapToPB(maps.SupportedIndicesMap))
		require.Equal(t, fetchedMaps.Maps.IndexIdentifierMap,
			fabrid_ext.IndexIdentifierMapToPB(maps.IndexIdentiferMap))

	})

}
