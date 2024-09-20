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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/private/path/fabridquery"
)

func TestAddExistingHop(t *testing.T) {
	ml := fabridquery.MatchList{SelectedPolicies: make([]*fabridquery.Policy, 5)}
	polIdx := 1
	ml.StorePolicy(1, &fabridquery.Policy{
		Type: fabridquery.STANDARD_POLICY_TYPE,
		Policy: &fabrid.Policy{
			IsLocal:    false,
			Identifier: 100,
			Index:      fabrid.PolicyID(polIdx),
		},
	})

	ml.StorePolicy(1, &fabridquery.Policy{
		Type: fabridquery.REJECT_POLICY_TYPE,
	})
	require.Equal(t, fabrid.PolicyID(polIdx), *ml.Policies()[1])
}

func TestRejectedHop(t *testing.T) {
	ml := fabridquery.MatchList{SelectedPolicies: make([]*fabridquery.Policy, 5)}
	polIdx := 1

	ml.StorePolicy(1, &fabridquery.Policy{
		Type: fabridquery.REJECT_POLICY_TYPE,
	})
	ml.StorePolicy(1, &fabridquery.Policy{
		Type: fabridquery.STANDARD_POLICY_TYPE,
		Policy: &fabrid.Policy{
			IsLocal:    false,
			Identifier: 100,
			Index:      fabrid.PolicyID(polIdx),
		},
	})
	require.NotEqual(t, fabrid.PolicyID(polIdx), *ml.Policies()[1])
	require.False(t, ml.Accepted())
}

func TestAcceptedHop(t *testing.T) {
	ml := fabridquery.MatchList{SelectedPolicies: make([]*fabridquery.Policy, 6)}
	for i := 0; i < 6; i++ {
		ml.StorePolicy(i, &fabridquery.Policy{
			Type: fabridquery.STANDARD_POLICY_TYPE,
			Policy: &fabrid.Policy{
				IsLocal:    false,
				Identifier: uint32(100 + i),
				Index:      fabrid.PolicyID(200 + i),
			},
		})
	}
	require.True(t, ml.Accepted())
	for i, pol := range ml.Policies() {
		require.Equal(t, fabrid.PolicyID(200+i), *pol)
	}
}
