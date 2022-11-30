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

package reservationstore

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	ct "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon/mock_daemon"
	"github.com/scionproto/scion/go/lib/drkey"
	fakedrkey "github.com/scionproto/scion/go/lib/drkey/fake"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestE2EBaseReqInitialMac(t *testing.T) {
	cases := map[string]struct {
		steps      base.PathSteps
		clientReq  libcol.BaseRequest
		transitReq e2e.Request
	}{
		"regular": {
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0),
			clientReq: libcol.BaseRequest{
				Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
				Index:     3,
				TimeStamp: util.SecsToTime(1),
				SrcHost:   net.ParseIP(srcHost()),
				DstHost:   net.ParseIP(dstHost()),
			},
			transitReq: e2e.Request{
				Request: *base.NewRequest(util.SecsToTime(1),
					ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
					3),
				SrcHost: net.ParseIP(srcHost()),
				DstHost: net.ParseIP(dstHost()),
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			mockDRKeys(t, daemon, srcIA(), net.ParseIP(srcHost()))

			err := tc.clientReq.CreateAuthenticators(ctx, daemon, tc.steps)
			require.NoError(t, err)
			// copy authenticators to transit request, as if they were received
			for i, a := range tc.clientReq.Authenticators {
				tc.transitReq.Authenticators[i] = a
			}

			authIA := tc.steps[1].IA
			auth := DRKeyAuthenticator{
				localIA:   authIA,
				fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
			}
			// second AS, first transit AS -> currentStep == 1
			ok, err := auth.ValidateE2ERequest(ctx, &tc.transitReq, tc.steps, 1)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2ESetupReqInitialMac(t *testing.T) {
	cases := map[string]struct {
		clientReq  libcol.E2EReservationSetup
		transitReq e2e.SetupReq
	}{
		"regular": {
			clientReq: libcol.E2EReservationSetup{
				BaseRequest: libcol.BaseRequest{
					Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
					Index:     3,
					TimeStamp: util.SecsToTime(1),
					SrcHost:   net.ParseIP(srcHost()),
					DstHost:   net.ParseIP(dstHost()),
				},
				Steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
					1, "1-ff00:0:112", 0),
				RequestedBW: 11,
				Segments: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
			transitReq: e2e.SetupReq{
				Request: e2e.Request{
					Request: *base.NewRequest(util.SecsToTime(1),
						ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
						3),
					SrcHost: net.ParseIP(srcHost()),
					DstHost: net.ParseIP(dstHost()),
				},
				Steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
					1, "1-ff00:0:112", 0),
				RequestedBW: 11,
				SegmentRsvs: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			mockDRKeys(t, daemon, srcIA(), net.ParseIP(srcHost()))

			err := tc.clientReq.CreateAuthenticators(ctx, daemon)
			require.NoError(t, err)
			// copy authenticators to transit request, as if they were received
			for i, a := range tc.clientReq.Authenticators {
				tc.transitReq.Authenticators[i] = a
			}

			authIA := tc.clientReq.Steps[1].IA
			auth := DRKeyAuthenticator{
				localIA:   authIA,
				fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
			}
			tc.transitReq.CurrentStep = 1 // second AS, first transit AS
			ok, err := auth.ValidateE2ESetupRequest(ctx, &tc.transitReq)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2ERequestTransitMac(t *testing.T) {
	cases := map[string]struct {
		transitReq e2e.Request
		steps      base.PathSteps
	}{
		"regular": {
			transitReq: e2e.Request{
				Request: *base.NewRequest(util.SecsToTime(1),
					ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
					3),
				SrcHost: net.ParseIP(srcHost()),
				DstHost: net.ParseIP(dstHost()),
			},
			steps: ct.NewSteps(
				0, "1-ff00:0:111", 1,
				1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0,
			),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// at the transit ASes:
			for step := 1; step < len(tc.steps); step++ {
				authIA := tc.steps[step].IA
				auth := DRKeyAuthenticator{
					localIA:   authIA,
					fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
				}
				err := auth.ComputeE2ERequestTransitMAC(ctx, &tc.transitReq, tc.steps, step)
				require.NoError(t, err)
			}

			// at the destination AS:
			dstIA := tc.steps.DstIA()
			auth := DRKeyAuthenticator{
				localIA:   dstIA,
				slowKeyer: fakeSlowKeyer{t: t, localIA: dstIA},
			}
			ok, err := auth.validateE2ERequestAtDestination(
				ctx,
				&tc.transitReq,
				tc.steps,
			)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2ESetupRequestTransitMac(t *testing.T) {
	cases := map[string]struct {
		transitReq e2e.SetupReq
	}{
		"regular": {
			transitReq: e2e.SetupReq{
				Request: e2e.Request{
					Request: *base.NewRequest(util.SecsToTime(1),
						ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
						3),
					SrcHost: net.ParseIP(srcHost()),
					DstHost: net.ParseIP(dstHost()),
				},
				Steps: ct.NewSteps(
					0, "1-ff00:0:111", 1,
					1, "1-ff00:0:110", 2,
					1, "1-ff00:0:112", 0,
				),
				RequestedBW: 11,
				SegmentRsvs: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// at the transit ASes:
			for step := 0; step < len(tc.transitReq.Steps); step++ {
				tc.transitReq.AllocationTrail = append(tc.transitReq.AllocationTrail, 11)
				if step == 0 {
					continue
				}
				tc.transitReq.CurrentStep = step
				authIA := tc.transitReq.Steps[step].IA
				auth := DRKeyAuthenticator{
					localIA:   authIA,
					fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
				}
				err := auth.ComputeE2ESetupRequestTransitMAC(ctx, &tc.transitReq)
				require.NoError(t, err)
			}

			// at the destination AS:
			tc.transitReq.CurrentStep = len(tc.transitReq.Steps) - 1
			dstIA := tc.transitReq.Steps.DstIA()
			auth := DRKeyAuthenticator{
				localIA:   dstIA,
				slowKeyer: fakeSlowKeyer{t: t, localIA: dstIA},
			}
			ok, err := auth.validateE2ESetupRequestAtDestination(
				ctx,
				&tc.transitReq,
			)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestComputeAndValidateResponse(t *testing.T) {
	cases := map[string]struct {
		res         base.Response
		steps       base.PathSteps
		currentStep int
	}{
		"regular": {
			res: &base.ResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 2),
				},
			},
			steps: ct.NewSteps(
				0, "1-ff00:0:111", 1,
				1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0,
			),
			currentStep: 0,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// at the transit ASes:
			for step := 1; step < len(tc.steps); step++ {
				tc.currentStep = step
				authIA := tc.steps[step].IA
				auth := DRKeyAuthenticator{
					localIA:   authIA,
					fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
				}
				err := auth.ComputeResponseMAC(ctx, tc.res, tc.steps.SrcIA(), tc.currentStep)
				require.NoError(t, err)
			}

			// at the initiator AS:
			srcIA := tc.steps.SrcIA()
			auth := DRKeyAuthenticator{
				localIA:   srcIA,
				slowKeyer: fakeSlowKeyer{t: t, localIA: srcIA},
			}
			tc.currentStep = 0
			ok, err := auth.ValidateResponse(ctx, tc.res, tc.steps)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestComputeAndValidateSegmentSetupResponse(t *testing.T) {
	cases := map[string]struct {
		res                   segment.SegmentSetupResponse
		steps                 base.PathSteps
		lastStepWhichComputes int
		currentStep           int
	}{
		"regular": {
			res: &segment.SegmentSetupResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 2),
				},
				Token: reservation.Token{
					InfoField: reservation.InfoField{
						PathType: reservation.CorePath,
						Idx:      3,
						// ...
					},
				},
			},
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0),
			lastStepWhichComputes: 2,
		},
		"failure": {
			res: &segment.SegmentSetupResponseFailure{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 2),
				},
				FailedStep: 2, // failed at 1-ff00:0:112
				Message:    "test message",
				FailedRequest: &segment.SetupReq{
					Request: base.Request{
						MsgId: base.MsgId{
							ID:        *ct.MustParseID("ff00:0:111", "01234567"),
							Index:     1,
							Timestamp: util.SecsToTime(1),
						},
						Authenticators: make([][]byte, 3),
					},
					ExpirationTime: util.SecsToTime(300),
					RLC:            1,
					PathType:       reservation.CorePath,
					MinBW:          5,
					MaxBW:          13,
					SplitCls:       11,
					Steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
						1, "1-ff00:0:112", 2, 1, "1-ff00:0:113", 0),

					PathProps: reservation.StartLocal | reservation.EndTransfer,
				},
			},
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 2,
				1, "1-ff00:0:113", 0), // note that we don't have drkeys for 113, but that drkey
			// should not be requested, as it is beyond the failure step.
			lastStepWhichComputes: 2,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// at the transit ASes:
			for step := len(tc.steps) - 1; step >= 0; step-- {
				tc.currentStep = step
				// if success, add a hop field
				if success, ok := tc.res.(*segment.SegmentSetupResponseSuccess); ok {
					currStep := tc.steps[tc.currentStep]
					success.Token.AddNewHopField(&reservation.HopField{
						Ingress: currStep.Ingress,
						Egress:  currStep.Egress,
						Mac:     [4]byte{255, uint8(step), 255, 255},
					})
				}
				if step > tc.lastStepWhichComputes || step == 0 {
					continue
				}
				authIA := tc.steps[step].IA
				auth := DRKeyAuthenticator{
					localIA:   authIA,
					fastKeyer: fakeFastKeyer{t: t, localIA: authIA},
				}
				err := auth.ComputeSegmentSetupResponseMAC(ctx, tc.res, tc.steps,
					tc.currentStep)
				require.NoError(t, err)
			}

			// at the initiator AS:
			srcIA := tc.steps.SrcIA()
			auth := DRKeyAuthenticator{
				localIA:   srcIA,
				slowKeyer: fakeSlowKeyer{t: t, localIA: srcIA},
			}
			tc.currentStep = 0
			ok, err := auth.ValidateSegmentSetupResponse(ctx, tc.res, tc.steps)
			require.NoError(t, err)
			require.True(t, ok, "validation failed")
		})
	}
}

func TestComputeAndValidateE2EResponseError(t *testing.T) {
	cases := map[string]struct {
		timestamp   time.Time
		response    base.Response
		steps       base.PathSteps
		srcHost     net.IP
		currentStep int
	}{
		"failure": {
			timestamp: util.SecsToTime(1),
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0),
			srcHost: xtest.MustParseIP(t, "10.1.1.1"),
			response: &base.ResponseFailure{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 3),
				},
				FailedStep: 1, // fail on ff00:0:110
				Message:    "test failure response",
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// colibri services, all ASes:
			for i := len(tc.steps) - 1; i >= 0; i-- { // from last to first
				step := tc.steps[i]
				tc.currentStep = i

				auth := DRKeyAuthenticator{
					localIA:   step.IA,
					fastKeyer: fakeFastKeyer{t: t, localIA: step.IA},
				}

				if failure, ok := tc.response.(*base.ResponseFailure); ok {
					if i > int(failure.FailedStep) {
						failure.Authenticators[i] = ([]byte)("won't check this")
						continue
					}
				}

				err := auth.ComputeE2EResponseMAC(ctx, tc.response, tc.currentStep,
					tc.steps.SrcIA(), addr.HostFromIP(tc.srcHost))
				require.NoError(t, err)
			}

			// initiator end-host:
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			mockDRKeys(t, daemon, srcIA(), tc.srcHost)

			switch res := tc.response.(type) {
			case *base.ResponseFailure:
				clientRes := &libcol.E2EResponseError{
					Authenticators: res.Authenticators,
					FailedAS:       int(res.FailedStep),
					Message:        res.Message,
				}
				err := clientRes.ValidateAuthenticators(ctx, daemon,
					tc.steps, tc.srcHost, tc.timestamp)
				require.NoError(t, err)
			}
		})
	}
}

func TestComputeAndValidateE2ESetupResponse(t *testing.T) {
	cases := map[string]struct {
		timestamp   time.Time
		response    e2e.SetupResponse
		steps       base.PathSteps
		srcHost     net.IP
		currentStep int
		rsvID       *reservation.ID    // success case only
		token       *reservation.Token // success case only
	}{
		"success": {
			timestamp: util.SecsToTime(1),
			response: &e2e.SetupResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 3), // same size as the path
				},
			},
			steps:   ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
			srcHost: xtest.MustParseIP(t, "10.1.1.1"),
			rsvID:   ct.MustParseID("ff00:0:111", "01234567890123456789abcd"),
			token: &reservation.Token{
				InfoField: reservation.InfoField{
					ExpirationTick: 11,
					Idx:            1,
					BWCls:          13,
					PathType:       reservation.CorePath,
					RLC:            7,
				},
			},
		},
		"failure_at_destination": {
			timestamp: util.SecsToTime(1),
			response: &e2e.SetupResponseFailure{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 3),
				},
				FailedStep: 2, // at ff00:0:112
				Message:    "this is a mock test message",
				AllocTrail: []reservation.BWCls{13, 5, 13},
			},
			steps:   ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
			srcHost: xtest.MustParseIP(t, "10.1.1.1"),
		},
		"failure_at_transit": {
			timestamp: util.SecsToTime(1),
			response: &e2e.SetupResponseFailure{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 3),
				},
				FailedStep: 1, // at ff00:0:110
				Message:    "this is a mock test message",
				AllocTrail: []reservation.BWCls{13, 5, 13},
			},
			steps:   ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
			srcHost: xtest.MustParseIP(t, "10.1.1.1"),
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			// mock the compuation of the drkey authenticator by the col service of all ASes.
			// walk in reverse from last to first AS.
			for i := len(tc.steps) - 1; i >= 0; i-- { // from last to first
				step := tc.steps[i]
				tc.currentStep = i
				switch res := tc.response.(type) {
				case *e2e.SetupResponseSuccess:
					tc.token.AddNewHopField(&reservation.HopField{
						Ingress: step.Ingress,
						Egress:  step.Egress,
						Mac:     [4]byte{255, 255, uint8(i), 255},
					})

					res.Token = tc.token.ToRaw()
				case *e2e.SetupResponseFailure:
					if i > int(res.FailedStep) {
						res.Authenticators[i] = ([]byte)("won't check this")
						continue
					}
				}

				auth := DRKeyAuthenticator{
					localIA:   step.IA,
					fastKeyer: fakeFastKeyer{t: t, localIA: step.IA},
				}
				err := auth.ComputeE2ESetupResponseMAC(ctx, tc.response, tc.currentStep,
					tc.steps.SrcIA(), addr.HostFromIP(tc.srcHost), tc.rsvID)
				require.NoError(t, err)
			}

			// initiator end-host:
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			mockDRKeys(t, daemon, srcIA(), tc.srcHost)

			switch res := tc.response.(type) {
			case *e2e.SetupResponseSuccess:
				colibriPath, err := e2e.DeriveColibriPath(tc.rsvID, tc.token).ToMinimal()
				require.NoError(t, err)
				require.NotNil(t, colibriPath)

				clientRes := &libcol.E2EResponse{
					Authenticators: res.Authenticators,
					ColibriPath: path.Path{
						DataplanePath: path.Colibri{
							ColibriPathMinimal: *colibriPath,
						},
					},
				}
				err = clientRes.ValidateAuthenticators(ctx, daemon,
					tc.steps, tc.srcHost,
					tc.timestamp)
				require.NoError(t, err)
			case *e2e.SetupResponseFailure:
				clientRes := &libcol.E2ESetupError{
					E2EResponseError: libcol.E2EResponseError{
						Authenticators: res.Authenticators,
						FailedAS:       int(res.FailedStep),
						Message:        res.Message,
					},
					AllocationTrail: res.AllocTrail,
				}
				err := clientRes.ValidateAuthenticators(ctx, daemon,
					tc.steps, tc.srcHost,
					tc.timestamp)
				require.NoError(t, err)
			}
		})
	}
}

func srcIA() addr.IA {
	return xtest.MustParseIA("1-ff00:0:111")
}

func srcHost() string {
	return "10.1.1.1"
}

func dstHost() string {
	return "10.2.2.2"
}

type fakeFastKeyer struct {
	t       *testing.T
	localIA addr.IA
}

func (f fakeFastKeyer) Lvl1Key(_ context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	if meta.SrcIA != f.localIA {
		require.FailNow(f.t, fmt.Sprintf("cannot derive, SrcIA != localIA, SrcIA=%s, localIA=%s",
			meta.SrcIA, f.localIA))
	}
	return fakedrkey.Lvl1Key(meta), nil
}

func (f fakeFastKeyer) ASHostKey(_ context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	if meta.SrcIA != f.localIA {
		require.FailNow(f.t, fmt.Sprintf("cannot derive, SrcIA != localIA, SrcIA=%s, localIA=%s",
			meta.SrcIA, f.localIA))
	}
	return fakedrkey.ASHost(meta), nil
}

type fakeSlowKeyer struct {
	t       *testing.T
	localIA addr.IA
}

func (f fakeSlowKeyer) Lvl1Key(_ context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	if meta.DstIA != f.localIA {
		require.FailNow(f.t, fmt.Sprintf("cannot fetch, DstIA != localIA, DstIA=%s, localIA=%s",
			meta.DstIA, f.localIA))
	}
	return fakedrkey.Lvl1Key(meta), nil
}

func mockDRKeys(t *testing.T, daemon *mock_daemon.MockConnector, localIA addr.IA, localIP net.IP) {
	t.Helper()

	fake := fakedrkey.Keyer{
		LocalIA: localIA,
		LocalIP: localIP,
	}
	daemon.EXPECT().DRKeyGetASHostKey(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(fake.DRKeyGetASHostKey)
}
