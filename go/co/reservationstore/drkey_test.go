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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	ct "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon/mock_daemon"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/stretchr/testify/require"
)

func TestE2eBaseReqInitialMac(t *testing.T) {
	cases := map[string]struct {
		clientReq  libcol.BaseRequest
		transitReq e2e.Request
	}{
		"regular": {
			clientReq: libcol.BaseRequest{
				Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
				Index:     3,
				TimeStamp: util.SecsToTime(1),
				Path:      ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
				SrcHost:   net.ParseIP(srcHost()),
				DstHost:   net.ParseIP(dstHost()),
			},
			transitReq: e2e.Request{
				Request: *base.NewRequest(util.SecsToTime(1),
					ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
					ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0)),
				SrcHost: net.ParseIP(srcHost()),
				DstHost: net.ParseIP(dstHost()),
			},
		},
	}
	mockKeys := mockKeysSlowIsSrc()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			tc.clientReq.CreateAuthenticators(ctx, daemon)
			// copy authenticators to transit request, as if they were received
			for i, a := range tc.clientReq.Authenticators {
				tc.transitReq.Authenticators[i] = a
			}
			auth := DrkeyAuthenticator{
				localIA:   tc.clientReq.Path.Steps[1].IA,
				connector: daemon,
			}
			tc.transitReq.Path.CurrentStep = 1 // second AS, first transit AS
			ok, err := auth.ValidateE2eRequest(ctx, &tc.transitReq)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2eSetupReqInitialMac(t *testing.T) {
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
					Path:      ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
					SrcHost:   net.ParseIP(srcHost()),
					DstHost:   net.ParseIP(dstHost()),
				},
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
						ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0)),
					SrcHost: net.ParseIP(srcHost()),
					DstHost: net.ParseIP(dstHost()),
				},
				RequestedBW: 11,
				SegmentRsvs: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
		},
	}
	mockKeys := mockKeysSlowIsSrc()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			tc.clientReq.CreateAuthenticators(ctx, daemon)
			// copy authenticators to transit request, as if they were received
			for i, a := range tc.clientReq.Authenticators {
				tc.transitReq.Authenticators[i] = a
			}
			auth := DrkeyAuthenticator{
				localIA:   tc.clientReq.Path.Steps[1].IA,
				connector: daemon,
			}
			tc.transitReq.Path.CurrentStep = 1 // second AS, first transit AS
			ok, err := auth.ValidateE2eSetupRequest(ctx, &tc.transitReq)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2eRequestTransitMac(t *testing.T) {
	cases := map[string]struct {
		transitReq e2e.Request
	}{
		"regular": {
			transitReq: e2e.Request{
				Request: *base.NewRequest(util.SecsToTime(1),
					ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
					ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0)),
				SrcHost: net.ParseIP(srcHost()),
				DstHost: net.ParseIP(dstHost()),
			},
		},
	}
	mockKeys := mockKeysSlowIsDst()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s->%s", meta.SrcIA, meta.DstIA)
					return k, nil
				})

			// at the transit ASes:
			for step := 1; step < len(tc.transitReq.Path.Steps); step++ {
				tc.transitReq.Path.CurrentStep = step
				auth := DrkeyAuthenticator{
					localIA:   tc.transitReq.Path.Steps[step].IA,
					connector: daemon,
				}
				err := auth.ComputeE2eRequestTransitMAC(ctx, &tc.transitReq)
				require.NoError(t, err)
			}

			// at the destination AS:
			tc.transitReq.Path.CurrentStep = len(tc.transitReq.Path.Steps) - 1
			auth := DrkeyAuthenticator{
				localIA:   tc.transitReq.Path.DstIA(),
				connector: daemon,
			}
			ok, err := auth.validateE2eRequestAtDestination(ctx, &tc.transitReq)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestE2eSetupRequestTransitMac(t *testing.T) {
	cases := map[string]struct {
		transitReq e2e.SetupReq
	}{
		"regular": {
			transitReq: e2e.SetupReq{
				Request: e2e.Request{
					Request: *base.NewRequest(util.SecsToTime(1),
						ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"), 3,
						ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0)),
					SrcHost: net.ParseIP(srcHost()),
					DstHost: net.ParseIP(dstHost()),
				},
				RequestedBW: 11,
				SegmentRsvs: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
		},
	}
	mockKeys := mockKeysSlowIsDst()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			// at the transit ASes:
			for step := 0; step < len(tc.transitReq.Path.Steps); step++ {
				tc.transitReq.AllocationTrail = append(tc.transitReq.AllocationTrail, 11)
				if step == 0 {
					continue
				}
				tc.transitReq.Path.CurrentStep = step
				auth := DrkeyAuthenticator{
					localIA:   tc.transitReq.Path.Steps[step].IA,
					connector: daemon,
				}
				err := auth.ComputeE2eSetupRequestTransitMAC(ctx, &tc.transitReq)
				require.NoError(t, err)
			}

			// at the destination AS:
			tc.transitReq.Path.CurrentStep = len(tc.transitReq.Path.Steps) - 1
			auth := DrkeyAuthenticator{
				localIA:   tc.transitReq.Path.DstIA(),
				connector: daemon,
			}
			ok, err := auth.validateE2eSetupRequestAtDestination(ctx, &tc.transitReq)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestComputeAndValidateResponse(t *testing.T) {
	cases := map[string]struct {
		res  base.Response
		path *base.TransparentPath
	}{
		"regular": {
			res: &base.ResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 2),
				},
			},
			path: ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
		},
	}
	mockKeys := mockKeysSlowIsSrc()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			// at the transit ASes:
			for step := 1; step < len(tc.path.Steps); step++ {
				tc.path.CurrentStep = step
				auth := DrkeyAuthenticator{
					localIA:   tc.path.Steps[step].IA,
					connector: daemon,
				}
				err := auth.ComputeResponseMAC(ctx, tc.res, tc.path)
				require.NoError(t, err)
			}

			// at the initiator AS:
			auth := DrkeyAuthenticator{
				localIA:   tc.path.SrcIA(),
				connector: daemon,
			}
			tc.path.CurrentStep = 0
			ok, err := auth.ValidateResponse(ctx, tc.res, tc.path)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestComputeAndValidateSegmentSetupResponse(t *testing.T) {
	cases := map[string]struct {
		res                   segment.SegmentSetupResponse
		path                  *base.TransparentPath
		lastStepWhichComputes int
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
			path:                  ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
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
						Path: ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
							1, "1-ff00:0:112", 2, 1, "1-ff00:0:113", 0),
						Authenticators: make([][]byte, 3),
					},
					ExpirationTime: util.SecsToTime(300),
					RLC:            1,
					PathType:       reservation.CorePath,
					MinBW:          5,
					MaxBW:          13,
					SplitCls:       11,
					PathAtSource: ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
						1, "1-ff00:0:112", 2, 1, "1-ff00:0:113", 0),
					PathProps: reservation.StartLocal | reservation.EndTransfer,
				},
			},
			path: ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 2,
				1, "1-ff00:0:113", 0), // note that we don't have drkeys for 113, but that drkey
			// should not be requested, as it is beyond the failure step.
			lastStepWhichComputes: 2,
		},
	}
	mockKeys := mockKeysSlowIsSrc()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			// at the transit ASes:
			for step := len(tc.path.Steps) - 1; step >= 0; step-- {
				tc.path.CurrentStep = step
				// if success, add a hop field
				if success, ok := tc.res.(*segment.SegmentSetupResponseSuccess); ok {
					currStep := tc.path.Steps[tc.path.CurrentStep]
					success.Token.AddNewHopField(&reservation.HopField{
						Ingress: currStep.Ingress,
						Egress:  currStep.Egress,
						Mac:     [4]byte{255, uint8(step), 255, 255},
					})
				}
				if step > tc.lastStepWhichComputes || step == 0 {
					continue
				}
				auth := DrkeyAuthenticator{
					localIA:   tc.path.Steps[step].IA,
					connector: daemon,
				}
				err := auth.ComputeSegmentSetupResponseMAC(ctx, tc.res, tc.path)
				require.NoError(t, err)
			}

			// at the initiator AS:
			auth := DrkeyAuthenticator{
				localIA:   tc.path.SrcIA(),
				connector: daemon,
			}
			tc.path.CurrentStep = 0
			ok, err := auth.ValidateSegmentSetupResponse(ctx, tc.res, tc.path)
			require.NoError(t, err)
			require.True(t, ok, "validation failed")
		})
	}
}

func TestComputeAndValidateE2eSetupResponse(t *testing.T) {
	cases := map[string]struct {
		timestamp time.Time
		response  e2e.SetupResponse
		rsvID     *reservation.ID
		path      *base.TransparentPath
		srcHost   net.IP
		token     *reservation.Token
	}{
		"success": {
			timestamp: util.SecsToTime(1),
			response: &e2e.SetupResponseSuccess{
				AuthenticatedResponse: base.AuthenticatedResponse{
					Timestamp:      util.SecsToTime(1),
					Authenticators: make([][]byte, 3), // same size as the path
				},
			},
			rsvID:   ct.MustParseID("ff00:0:111", "01234567890123456789abcd"),
			path:    ct.NewPath(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112", 0),
			srcHost: xtest.MustParseIP(t, "10.1.1.1"),
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
	}

	mockKeys := mockKeysSlowIsSrc()
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			daemon := mock_daemon.NewMockConnector(ctrl)
			daemon.EXPECT().DRKeyGetLvl2Key(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, meta drkey.Lvl2Meta, ts time.Time) (
					drkey.Lvl2Key, error) {

					k, ok := mockKeys[fastSlow{fast: meta.SrcIA, slow: meta.DstIA}]
					require.True(t, ok, "not found %s", meta.SrcIA)
					return k, nil
				})

			// colibri services, all ASes:
			for i := len(tc.path.Steps) - 1; i >= 0; i-- { // from last to first
				step := tc.path.Steps[i]
				tc.path.CurrentStep = i
				tc.token.AddNewHopField(&reservation.HopField{
					Ingress: step.Ingress,
					Egress:  step.Egress,
					Mac:     [4]byte{255, 255, uint8(i), 255},
				})
				if success, ok := tc.response.(*e2e.SetupResponseSuccess); ok {
					buff := make([]byte, tc.token.Len())
					_, err := tc.token.Read(buff)
					require.NoError(t, err)
					success.Token = buff
				}
				auth := DrkeyAuthenticator{
					localIA:   tc.path.Steps[i].IA,
					connector: daemon,
				}
				err := auth.ComputeE2eSetupResponseMAC(ctx, tc.response, tc.path,
					addr.HostFromIP(tc.srcHost), tc.rsvID)
				require.NoError(t, err)
			}

			// initiator end-host:
			var authenticators [][]byte
			if success, ok := tc.response.(*e2e.SetupResponseSuccess); ok {
				success.Token = tc.token.ToRaw()
				authenticators = tc.response.(*e2e.SetupResponseSuccess).Authenticators
				success.Authenticators = authenticators
			}
			colibriPath := e2e.DeriveColibriPath(tc.rsvID, tc.token)
			serializedColPath := make([]byte, colibriPath.Len())
			err := colibriPath.SerializeTo(serializedColPath)
			require.NoError(t, err)

			clientRes := &libcol.E2EResponse{
				Authenticators: authenticators,
				ColibriPath: path.Path{
					SPath: spath.Path{
						Raw:  serializedColPath,
						Type: colibriPath.Type(),
					},
				},
			}
			err = clientRes.ValidateAuthenticators(ctx, daemon, tc.path, tc.srcHost, tc.timestamp)
			require.NoError(t, err)
		})
	}
	// e2e.DeriveColibriPath(id,token)
}

func srcIA() string {
	return "1-ff00:0:111"
}

func dstIA() string {
	return "1-ff00:0:112"
}

func srcHost() string {
	return "10.1.1.1"
}

func dstHost() string {
	return "10.2.2.2"
}

type fastSlow struct {
	fast addr.IA
	slow addr.IA
}

// mockKeysSlowIsSrc uses AS 1-ff00:0:111 as slow path.
func mockKeysSlowIsSrc() map[fastSlow]drkey.Lvl2Key {
	as1 := xtest.MustParseIA(srcIA())
	as2 := xtest.MustParseIA("1-ff00:0:110")
	as3 := xtest.MustParseIA("1-ff00:0:112")
	host1 := addr.HostFromIPStr(srcHost())

	return map[fastSlow]drkey.Lvl2Key{
		{fast: as1, slow: as1}: mockKey(drkey.AS2AS, as1, as1, host1),
		{fast: as2, slow: as1}: mockKey(drkey.AS2AS, as2, as1, host1),
		{fast: as3, slow: as1}: mockKey(drkey.AS2AS, as3, as1, host1),
	}
}

// mockKeysSlowIsDst uses AS 1-ff00:0:112 as slow path.
func mockKeysSlowIsDst() map[fastSlow]drkey.Lvl2Key {
	as1 := xtest.MustParseIA("1-ff00:0:111")
	as2 := xtest.MustParseIA("1-ff00:0:110")
	as3 := xtest.MustParseIA(dstIA())
	host3 := addr.HostFromIPStr(dstHost())

	return map[fastSlow]drkey.Lvl2Key{
		{fast: as1, slow: as3}: mockKey(drkey.AS2AS, as1, as3, host3),
		{fast: as2, slow: as3}: mockKey(drkey.AS2AS, as2, as3, host3),
		{fast: as3, slow: as3}: mockKey(drkey.AS2AS, as3, as3, host3),
	}
}

func mockKey(keyType drkey.Lvl2KeyType, fast, slow addr.IA, slowhost addr.HostAddr) drkey.Lvl2Key {
	k := xtest.MustParseHexString("0123456789abcdef0123456789abcdef") // 16 bytes
	fast.Write(k[:8])
	slow.Write(k[8:])
	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  keyType,
			Protocol: "colibri",
			Epoch:    drkey.NewEpoch(0, 100),
			SrcIA:    fast,
			DstIA:    slow,
			DstHost:  slowhost,
		},
		Key: k,
	}
}
