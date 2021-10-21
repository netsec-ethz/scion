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

package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/client/sorting"
	ct "github.com/scionproto/scion/go/lib/colibri/coltest"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon/mock_daemon"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewReservation(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	srcHost := xtest.MustParseIP(t, "192.0.2.1")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	dstHost := xtest.MustParseIP(t, "192.0.2.10")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	daemon := mock_daemon.NewMockConnector(ctrl)
	daemon.EXPECT().ColibriListRsvs(gomock.Any(), gomock.Any()).Return(
		ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
			ct.WithUpSegs(1),
		), nil)

	rsv, err := NewReservation(ctx, daemon, srcIA, srcHost, dstIA, dstHost, 11, 0,
		sorting.ByExpiration)
	require.NoError(t, err)
	require.True(t, rsv.request.Id.IsE2EID())
	require.Equal(t, dstIA, rsv.dstIA)
	require.Nil(t, rsv.colibriPath) // not negotiated yet

	require.NotNil(t, rsv.request) // should be populated
	require.Equal(t, dstIA, rsv.request.Path.DstIA())
	require.Equal(t, srcIA, rsv.request.Path.SrcIA())
	require.Greater(t, len(rsv.request.Segments), 0)
}

func TestReservationOpen(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	srcHost := xtest.MustParseIP(t, "192.0.2.1")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	dstHost := xtest.MustParseIP(t, "192.0.2.10")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	daemon := mock_daemon.NewMockConnector(ctrl)
	daemon.EXPECT().ColibriListRsvs(gomock.Any(), gomock.Any()).Return(
		ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
			ct.WithUpSegs(1),
		), nil)

	rsv, err := NewReservation(ctx, daemon, srcIA, srcHost, dstIA, dstHost, 11, 0,
		sorting.ByExpiration)
	require.NoError(t, err)

	// modify the global task duration for the test
	rsv.e2eRenewalTaskDuration = reservation.TicksInE2ERsv * 4 * time.Millisecond / 2 // 16ms

	testPaths := []*snetpath.Path{
		{DataplanePath: snet.RawPath{Raw: xtest.MustParseHexString("01")}},
		{DataplanePath: snet.RawPath{Raw: xtest.MustParseHexString("02")}},
		{DataplanePath: snet.RawPath{Raw: xtest.MustParseHexString("03")}},
	}
	timesCalled := 0
	daemon.EXPECT().ColibriSetupRsv(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, req *colibri.E2EReservationSetup) (snet.Path, error) {
			// check that the index increments monotonically
			timesAsIndex := reservation.IndexNumber(0).Add(reservation.IndexNumber(timesCalled))
			require.Equal(t, timesAsIndex, req.Index)
			// return an identifiable path for the test
			p := testPaths[len(testPaths)-1]
			if timesCalled < len(testPaths) {
				p = testPaths[timesCalled]
			}
			timesCalled++
			return p, nil

		})

	err = rsv.Open(ctx, nil, func(r *Reservation, err error) *colibri.FullTrip {
		require.Fail(t, "should not fail")
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, timesCalled, 1)
	require.Equal(t, testPaths[0], rsv.colibriPath)

	// now wait e2eRenewalTaskDuration + a bit
	time.Sleep(rsv.e2eRenewalTaskDuration * 3)
	require.Greater(t, timesCalled, 1)
	require.Equal(t, testPaths[2], rsv.colibriPath) // last path available before the error

	// stop and check
	daemon.EXPECT().ColibriCleanupRsv(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, id *reservation.ID, idx reservation.IndexNumber) error {
			require.Equal(t, rsv.request.Id, *id)
			require.Equal(t, reservation.NewIndexNumber(timesCalled-1), idx)
			return nil
		})
	err = rsv.Close(ctx)
	require.NoError(t, err)
}

func TestReservationOpenSuccessfully(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	srcHost := xtest.MustParseIP(t, "192.0.2.1")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	dstHost := xtest.MustParseIP(t, "192.0.2.10")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	daemon := mock_daemon.NewMockConnector(ctrl)
	daemon.EXPECT().ColibriListRsvs(gomock.Any(), gomock.Any()).Return(
		ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
			ct.WithUpSegs(1),
		), nil)

	rsv, err := NewReservation(ctx, daemon, srcIA, srcHost, dstIA, dstHost, 11, 0,
		sorting.ByExpiration)
	require.NoError(t, err)
	// modify the global task duration for the test
	rsv.e2eRenewalTaskDuration = reservation.TicksInE2ERsv * 4 * time.Millisecond / 2 // 16ms

	returnPath := &snetpath.Path{
		DataplanePath: snet.RawPath{Raw: xtest.MustParseHexString("01")},
	}
	timesCalled := 0
	daemon.EXPECT().ColibriSetupRsv(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, req *colibri.E2EReservationSetup) (snet.Path, error) {
			timesCalled++
			return returnPath, nil
		})

	renewalsCalled := 0
	err = rsv.Open(ctx, func(*Reservation) {
		renewalsCalled++
	}, nil)
	require.NoError(t, err)
	require.Equal(t, timesCalled, 1)
	require.Equal(t, returnPath, rsv.colibriPath)

	// now wait e2eRenewalTaskDuration + a bit
	time.Sleep(rsv.e2eRenewalTaskDuration * 3)
	require.Greater(t, timesCalled, 1)
	require.Equal(t, returnPath, rsv.colibriPath)
	require.Equal(t, timesCalled-1, renewalsCalled)

	// stop and check
	daemon.EXPECT().ColibriCleanupRsv(gomock.Any(), gomock.Any()).Return(nil)
	err = rsv.Close(ctx)
	require.NoError(t, err)
}

func TestReservationFailOnRenewal(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	srcHost := xtest.MustParseIP(t, "192.0.2.1")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	dstHost := xtest.MustParseIP(t, "192.0.2.10")
	stitchables := ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1, 1), // two up
	)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	daemon := mock_daemon.NewMockConnector(ctrl)
	daemon.EXPECT().ColibriListRsvs(gomock.Any(), gomock.Any()).Return(
		stitchables, nil)
	ct.NewStitchableSegments("1-ff00:0:111", "1-ff00:0:112",
		ct.WithUpSegs(1),
	)

	trips := colibri.CombineAll(stitchables)
	// unsorted; will use [0] :
	rsv, err := NewReservation(ctx, daemon, srcIA, srcHost, dstIA, dstHost, 11, 0)
	require.NoError(t, err)

	// modify the global task duration for the test
	rsv.e2eRenewalTaskDuration = reservation.TicksInE2ERsv * 4 * time.Millisecond / 2 // 16ms

	testPaths := []*snetpath.Path{
		{DataplanePath: snet.RawPath{Raw: xtest.MustParseHexString("01")}},
	}
	testPathAfterFailure := &snetpath.Path{DataplanePath: snet.RawPath{
		Raw: xtest.MustParseHexString("02")},
	}
	timesCalled := 0
	everFailed := false
	timesCalledAfterFailure := 0
	doFailAgain := false
	daemon.EXPECT().ColibriSetupRsv(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, req *colibri.E2EReservationSetup) (snet.Path, error) {
			timesCalled++
			if everFailed {
				timesCalledAfterFailure++
				if doFailAgain {
					return nil, serrors.New("mock error 2")
				}
				return testPathAfterFailure, nil
			}
			if timesCalled > len(testPaths) {
				return nil, serrors.New("mock error 1")
			}
			return testPaths[timesCalled-1], nil
		})

	waitForFallback := sync.WaitGroup{}
	waitForFallback.Add(1)
	waitForTest := sync.WaitGroup{}
	waitForTest.Add(1)
	err = rsv.Open(ctx, nil, func(r *Reservation, err error) *colibri.FullTrip {
		if !everFailed {
			defer waitForFallback.Done()
			everFailed = true
			return trips[1]
		}
		// sync with the test
		waitForTest.Wait()
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, timesCalled, 1)
	require.Equal(t, testPaths[0], rsv.colibriPath)
	require.Equal(t, 0, timesCalledAfterFailure)
	require.NotEqual(t, trips[1].Segments(), rsv.request.Segments)

	waitForFallback.Wait() // wait until the fallback function is done
	require.Equal(t, true, everFailed)
	require.Equal(t, testPathAfterFailure, rsv.colibriPath) // after first failure
	// sleep more to allow the routine to finish setting the rsv.
	time.Sleep(10 * time.Millisecond)
	require.Greater(t, timesCalledAfterFailure, 0)
	require.Equal(t, trips[1].Segments(), rsv.request.Segments)
	require.NotNil(t, rsv.runner)

	// unlock second part of the test, where the fallback function will fail
	waitForTest.Done()
	time.Sleep(10 * time.Millisecond)                       // wait  to allow the runner to finish
	require.Equal(t, testPathAfterFailure, rsv.colibriPath) // last valid path before full failure

	// this is  a bit of a hack: changing here the onError function
	alwaysFailing := false
	rsv.onError = func(rsv *Reservation, err error) *colibri.FullTrip {
		alwaysFailing = true
		return nil
	}
	doFailAgain = true
	// and wait for 2 periods
	time.Sleep(2 * rsv.e2eRenewalTaskDuration)
	require.Equal(t, true, alwaysFailing)
	// because it failed:
	require.Nil(t, rsv.runner)
}
