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

package fabridquery

import (
	"github.com/scionproto/scion/pkg/experimental/fabrid"
)

type MatchList struct {
	SelectedPolicies []*Policy
}

// Copy creates a copy of the MatchList object, including the list of selected policies.
func (ml MatchList) Copy() *MatchList {
	duplicate := make([]*Policy, len(ml.SelectedPolicies))
	copy(duplicate, ml.SelectedPolicies)
	return &MatchList{duplicate}
}

// StorePolicy only stores a policy if there has not been one already set for the hop.
func (ml MatchList) StorePolicy(hop int, policy *Policy) {
	if ml.SelectedPolicies[hop] == nil {
		ml.SelectedPolicies[hop] = policy
	}
}

// Accepted checks if all hops have at least a policy assigned, which is not the rejection policy
func (ml MatchList) Accepted() bool {
	for _, policy := range ml.SelectedPolicies {
		if policy != nil && policy.Type == REJECT_POLICY_TYPE {
			return false
		}
	}
	return true
}

// Policies returns a slice of PolicyIDs representing the policies used in each hop of
// the MatchList object. A zero PolicyID is used for a nil selected policy, and a zero
// or reject PolicyID is used when a wildcard or reject policy is selected.
// For other policies, the PolicyID is obtained from the selected policy's Policy.Index field.
// It also prints the index and policy details of each hop to console.
// The returned slice has the same length as the MatchList.SelectedPolicies slice.
// func (ml MatchList) Policies() (pols []*fabrid.PolicyID) {}
func (ml MatchList) Policies() (pols []*fabrid.PolicyID) {
	pols = make([]*fabrid.PolicyID, len(ml.SelectedPolicies))
	for i, selected := range ml.SelectedPolicies {
		if selected == nil {
			pols[i] = nil
		} else if selected.Type == WILDCARD_POLICY_TYPE || selected.Type == REJECT_POLICY_TYPE {
			zeroPol := fabrid.PolicyID(0)
			pols[i] = &zeroPol
		} else {
			pols[i] = &selected.Policy.Index
		}
	}
	return pols
}
