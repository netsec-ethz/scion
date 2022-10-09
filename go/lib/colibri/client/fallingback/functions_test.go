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
	"context"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	rt "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/client"
	ct "github.com/scionproto/scion/go/lib/colibri/coltest"
	"github.com/scionproto/scion/go/lib/daemon/mock_daemon"
	fakedrkey "github.com/scionproto/scion/go/lib/drkey/fake"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestCaptureTrips(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	srcHost := xtest.MustParseIP(t, "192.0.2.1")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	dstHost := xtest.MustParseIP(t, "192.0.2.10")
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		// 1 direct trip, + 2 thru core
		ct.WithCoreASes("1-ff00:0:110", "1-ff00:0:100"),

		ct.WithUpSegs(1, 2, 3),

		ct.WithDownSegs(2, 3),
	)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	daemon := mock_daemon.NewMockConnector(ctrl)
	daemon.EXPECT().ColibriListRsvs(gomock.Any(), gomock.Any()).Return(stitchables, nil)
	fake := fakedrkey.Keyer{
		LocalIA: srcIA,
		LocalIP: srcHost,
	}
	daemon.EXPECT().DRKeyGetASHostKey(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(fake.DRKeyGetASHostKey)

	capturedTrips := make([]*colibri.FullTrip, 0)
	_, err := client.NewReservation(ctx, daemon, srcIA, srcHost, dstIA, dstHost, 11, 0,
		CaptureTrips(&capturedTrips))
	require.NoError(t, err)
	require.Len(t, capturedTrips, 3) // three trips?
	// check the order is the same
	fullTrips := colibri.CombineAll(stitchables)
	sort.SliceStable(fullTrips, func(i, j int) bool {
		return false
	})
	require.Equal(t, fullTrips, capturedTrips)
}

func TestToNext(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		// 1 direct trip, + 2 thru core
		ct.WithCoreASes("1-ff00:0:110", "1-ff00:0:100"),

		ct.WithUpSegs(1, 2, 3),

		ct.WithDownSegs(2, 3),
	)
	capturedTrips := colibri.CombineAll(stitchables)

	fallbackFcn := ToNext(capturedTrips)
	require.Equal(t, capturedTrips[1], fallbackFcn(nil, nil))
	require.Equal(t, capturedTrips[2], fallbackFcn(nil, nil))
}

func TestSkipInterface(t *testing.T) {
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpPaths(rt.NewSteps(0, "1-ff00:0:111", 2, 2, "1-ff00:0:112", 0),
			rt.NewSteps(0, "1-ff00:0:111", 2, 1, "1-ff00:0:110", 0),
			rt.NewSteps(0, "1-ff00:0:111", 3, 1, "1-ff00:0:100", 0)),
		ct.WithDownPaths(rt.NewSteps(0, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
			rt.NewSteps(0, "1-ff00:0:100", 2, 1, "1-ff00:0:112", 0)),
	)
	capturedTrips := colibri.CombineAll(stitchables)

	require.Len(t, capturedTrips, 3)
	require.Len(t, *capturedTrips[0], 1)
	require.Len(t, *capturedTrips[1], 2)
	require.Len(t, *capturedTrips[2], 2)

	fallbackFcn := SkipInterface(capturedTrips)
	rsv := client.NewReservationForTesting(nil, time.Hour, nil, 0,
		nil, capturedTrips[0], nil, nil, nil)
	admissionFailure := &colibri.E2ESetupError{
		E2EResponseError: colibri.E2EResponseError{
			Message:  "mock",
			FailedAS: 0, // the first step failed,in: 0, eg:2 of 1-ff00:0:111
		},
	}
	nextTrip := fallbackFcn(rsv, admissionFailure)
	require.Equal(t, capturedTrips[2], nextTrip)
}
