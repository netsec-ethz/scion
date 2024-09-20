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

package fabridquery_test

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/path/fabridquery"
)

type PathProvider struct {
	g *graph.Graph
}

func NewPathProvider(ctrl *gomock.Controller) PathProvider {
	return PathProvider{
		g: graph.NewDefaultGraph(ctrl),
	}
}

func (p PathProvider) GetHops(src, dst addr.IA) [][]snet.HopInterface {
	result := [][]snet.HopInterface{}
	paths := p.g.GetPaths(src.String(), dst.String())
	for _, ifids := range paths {
		pathIntfs := make([]snet.PathInterface, 0, len(ifids))
		for _, ifid := range ifids {
			ia := p.g.GetParent(ifid)
			pathIntfs = append(pathIntfs, snet.PathInterface{
				IA: ia,
				ID: common.IFIDType(ifid),
			})
		}
		fabridInfo := make([]snet.FabridInfo, 0, len(pathIntfs)/2)
		fabridInfo = append(fabridInfo, snet.FabridInfo{
			Enabled:  true,
			Detached: false,
			Digest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
				0x13, 0x14, 0x15, 0x16},
			Policies: []*fabrid.Policy{},
		})
		for i := 1; i < len(pathIntfs)-1; i += 2 {
			fabridInfo = append(fabridInfo, snet.FabridInfo{
				Enabled:  true,
				Detached: false,
				Digest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
					0x12, 0x13, 0x14, 0x15, 0x16},
				Policies: p.g.FabridPolicy(uint16(pathIntfs[i].ID),
					uint16(pathIntfs[i+1].ID)),
			})
		}
		fabridInfo = append(fabridInfo, snet.FabridInfo{
			Enabled:  true,
			Detached: false,
			Digest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
				0x13, 0x14, 0x15, 0x16},
			Policies: p.g.FabridPolicy(uint16(pathIntfs[len(
				pathIntfs)-1].ID), 0),
		})
		metadata := snet.PathMetadata{
			Interfaces: pathIntfs,
			FabridInfo: fabridInfo,
		}
		result = append(result, metadata.Hops())
	}
	return result
}

func TestParseFabridQuery(t *testing.T) {
	tests := map[string]struct {
		Input       string
		ExpPolicies []fabrid.PolicyID
		Src         addr.IA
		Dst         addr.IA
		ExpectError bool
		Accept      bool
		NilPolicies []bool
	}{
		"Wildcard": {
			Input: "0-0#0,0@0",
			Src:   xtest.MustParseIA("1-ff00:0:133"),
			Dst:   xtest.MustParseIA("1-ff00:0:131"),
			ExpPolicies: []fabrid.PolicyID{
				fabrid.PolicyID(0),
				fabrid.PolicyID(0),
				fabrid.PolicyID(0),
			},
			NilPolicies: []bool{false, false, false},
			Accept:      true,
			ExpectError: false,
		},
		"Reject All": {
			Input: "0-0#0,0@REJECT",
			Src:   xtest.MustParseIA("1-ff00:0:133"),
			Dst:   xtest.MustParseIA("1-ff00:0:131"),
			ExpPolicies: []fabrid.PolicyID{
				fabrid.PolicyID(0),
				fabrid.PolicyID(0),
				fabrid.PolicyID(0),
			},
			NilPolicies: []bool{false, false, false},
			Accept:      false,
			ExpectError: false,
		},
		"Global policy": {
			Input: "0-0#0,0@G1",
			Src:   xtest.MustParseIA("1-ff00:0:133"),
			Dst:   xtest.MustParseIA("1-ff00:0:131"),
			ExpPolicies: []fabrid.PolicyID{
				fabrid.PolicyID(0x28),
				fabrid.PolicyID(0x28),
				fabrid.PolicyID(0x0),
			},
			NilPolicies: []bool{true, false, false},
			Accept:      true,
			ExpectError: false,
		},
		//TODO(jvanbommel): extend
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			hops := pp.GetHops(tc.Src, tc.Dst)[0]
			expr, err := fabridquery.ParseFabridQuery(tc.Input)
			if tc.ExpectError {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			ml := fabridquery.MatchList{
				SelectedPolicies: make([]*fabridquery.Policy, len(hops)),
			}
			_, resMl := expr.Evaluate(hops, &ml)
			fmt.Println(resMl.SelectedPolicies)
			require.Equal(t, tc.Accept, resMl.Accepted())
			if !tc.Accept {
				return
			}
			pols := resMl.Policies()
			for i, pol := range tc.ExpPolicies {
				if tc.NilPolicies[i] {
					require.True(t, pols[i] == nil)
					continue
				}
				require.Equal(t, pol, *pols[i])
			}
		})
	}
}
