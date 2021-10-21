// Copyright 2021 ETH Zurich
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

package fallingback

import (
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/client"
)

func CaptureTrips(fullTripsStorage *[]*colibri.FullTrip) client.LessFunction {
	localSet := make(map[string]struct{})
	return func(a, b colibri.FullTrip) bool {
		ah := hash(a)
		bh := hash(b)
		if _, ok := localSet[bh]; !ok {
			localSet[bh] = struct{}{}
			*fullTripsStorage = append(*fullTripsStorage, &b)
		}
		if _, ok := localSet[ah]; !ok {
			localSet[ah] = struct{}{}
			*fullTripsStorage = append(*fullTripsStorage, &a)
		}
		return false // don't alter the ordering
	}
}

// ToNext returns a fallback that will simply retry with the next available full trip,
// as they were sorted initially.
func ToNext(trips []*colibri.FullTrip) client.RenewalErrorHandler {
	current := 0
	return func(r *client.Reservation, err error) *colibri.FullTrip {
		current++
		if current < len(trips) {
			return trips[current]
		}
		return nil
	}
}

// SkipInterface returns a fallback that will attempt to avoid a failing interface, if
// the error was an admission error (the most common).
// This is useful because skipping failing interfaces will probably yield a different result
// than the admission failure we observe in the error.
func SkipInterface(trips []*colibri.FullTrip) client.RenewalErrorHandler {
	return func(r *client.Reservation, err error) *colibri.FullTrip {
		failure, ok := err.(*colibri.E2ESetupError)
		if !ok {
			return nil
		}
		// find the failing interface
		var failingStep *base.PathStep
		currTrip := r.CurrentTrip()
		failedAS := failure.FailedAS
		for i := 0; i < len(currTrip); i++ {
			if failedAS < len(currTrip[i].PathSteps) {
				failingStep = &currTrip[i].PathSteps[failedAS]
				break
			}
			failedAS -= len(currTrip) - 1
		}
		if failingStep == nil {
			// unexpected error. Failing step should always be part of the path
			return nil
		}
		// find a trip without that interface
		for _, t := range trips {
			if !hasInterface(t, failingStep) {
				return t
			}
		}
		return nil // none found
	}
}

func hash(ft colibri.FullTrip) string {
	s := ""
	for _, t := range ft {
		s += t.Id.String() + "|"
	}
	return s
}

// hasInterface returns true if both ingress and egress for that IA are present in the trip.
func hasInterface(trip *colibri.FullTrip, iface *base.PathStep) bool {
	for _, l := range *trip {
		for _, step := range l.PathSteps {
			if step.IA == iface.IA &&
				(step.Egress == iface.Egress && step.Ingress == iface.Ingress) {

				return true
			}
		}
	}
	return false
}
