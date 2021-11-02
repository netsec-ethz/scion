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
	ct "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon/mock_daemon"
	"github.com/scionproto/scion/go/lib/drkey"
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
	mockKeys := mockKeysSameSlowPath()
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
	mockKeys := mockKeysSameSlowPath()
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
	mockKeys := mockKeysSameSlowPath()
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
	mockKeys := mockKeysSameSlowPath()
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
	mockKeys := mockKeysSameSlowPath()
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

// mockKeysSameSlowPath uses AS 1-ff00:0:111 as slow path.
func mockKeysSameSlowPath() map[fastSlow]drkey.Lvl2Key {
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
