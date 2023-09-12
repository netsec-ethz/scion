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

package hummingbird_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/hummingbird"
	hbirddp "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet/path"
)

func TestReservationWithScionPath(t *testing.T) {
	scionPath := getScionSnetPath(t)

	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, flyoverSliceToMap(testFlyoversInDB)),
	)
	assert.NoError(t, err)

	// Check that the derived path in the reservation is the same as hbirdPath (which is the
	// expected one).
	hbirdPath, err := getHbirdFlyoversSnetPath(t, fixedTime)
	assert.NoError(t, err)
	decoded := r.DeriveDataPlanePath(16, fixedTime)
	raw := path.Hummingbird{
		Raw: make([]byte, decoded.Len()),
	}
	err = decoded.SerializeTo(raw.Raw)
	assert.NoError(t, err)
	scionPath.DataplanePath = raw

	assert.Equal(t, hbirdPath, scionPath)

	// Check that the number of flyovers, nil or otherwise, is the same as hop fields.
	flyovers := r.FlyoverPerHopField()
	assert.Equal(t, len(decodedScionTestPath.HopFields), len(flyovers))
}

func TestReservationWithScionPathNoFlyovers(t *testing.T) {
	scionPath := getScionSnetPath(t)

	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, nil), // nil == "no flyovers"
	)
	assert.NoError(t, err)

	// Should not have any flyoverCount, but the same amount of hop fields in the dataplane.
	flyoverCount, hfCount := r.FlyoverAndHFCount()
	assert.Equal(t, 0, flyoverCount)
	assert.Equal(t, decodedScionTestPath.NumHops, hfCount)

	// All hop fields must not be flyovers.
	decoded := r.DeriveDataPlanePath(16, fixedTime)
	for i, hf := range decoded.HopFields {
		assert.False(t, hf.Flyover, "failed at index %d", i)
	}

	// Check reconstruction from parts.
	// First create a reservation from no flyovers again.
	rOrig, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, nil), // nil == "no flyovers"
	)
	assert.NoError(t, err)

	// Now create a reservation from an existing hummingbird path and flyovers.
	flyovers := r.FlyoverPerHopField()
	r2, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithExistingHbirdPath(decoded, flyovers),
	)
	assert.NoError(t, err)
	// And derive a hummingbird path from both reservations.
	expected := rOrig.DeriveDataPlanePath(16, fixedTime)
	got := r2.DeriveDataPlanePath(16, fixedTime)
	assert.Equal(t, expected, got)
}

func TestReservationWithHbirdPath(t *testing.T) {
	// Build a Reservation from an existing decoded hummingbird path and its associated
	// flyover sequence.
	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithExistingHbirdPath(
			decodedHbirdTestPathFlyovers,
			testExpectedFlyovers),
	)
	assert.NoError(t, err)

	// Expected:
	expected, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(getScionSnetPath(t),
			flyoverSliceToMap(testFlyoversInDB),
		),
	)
	assert.NoError(t, err)
	assert.Equal(t, expected, r)
}

func TestDeriveDataPlanePath(t *testing.T) {
	// New reservation with a scion path.
	scionPath := getScionSnetPath(t)
	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, flyoverSliceToMap(testFlyoversInDB)),
	)
	assert.NoError(t, err)

	// Run twice.
	for i := 0; i < 2; i++ {
		// Derive dataplane path.
		decoded := r.DeriveDataPlanePath(16, fixedTime)

		// Check that it is a valid path.
		buf := make([]byte, decoded.Len())
		err = decoded.SerializeTo(buf)
		assert.NoError(t, err)
		// Deserialize to hummingbird Decoded.
		decoded = &hbirddp.Decoded{}
		err = decoded.DecodeFromBytes(buf)
		assert.NoError(t, err)
		// Deserialize to hummingbird Raw.
		hbirdRaw := hbirddp.Raw{}
		err = hbirdRaw.DecodeFromBytes(buf)
		assert.NoError(t, err)
	}
}

func TestDeriveDataPlanePathNoFlyovers(t *testing.T) {
	// New reservation with a scion path.
	scionPath := getScionSnetPath(t)
	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, nil),
	)
	assert.NoError(t, err)

	// Derive dataplane path.
	decoded := r.DeriveDataPlanePath(16, fixedTime)

	// Check that it is a valid path.
	buf := make([]byte, decoded.Len())
	err = decoded.SerializeTo(buf)
	assert.NoError(t, err)
	// Deserialize to hummingbird Decoded.
	decoded = &hbirddp.Decoded{}
	err = decoded.DecodeFromBytes(buf)
	assert.NoError(t, err)
	// Deserialize to hummingbird Raw.
	hbirdRaw := hbirddp.Raw{}
	err = hbirdRaw.DecodeFromBytes(buf)
	assert.NoError(t, err)
}

func flyoverSliceToMap(flyovers []hummingbird.Flyover) hummingbird.FlyoverMap {
	m := make(hummingbird.FlyoverMap)
	for _, flyover := range flyovers {
		clone := flyover
		m[clone.BaseHop] = append(m[clone.BaseHop], &clone)
	}
	return m
}
