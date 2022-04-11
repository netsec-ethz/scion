// Copyright 2020 ETH Zurich
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

package grpc_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"inet.af/netaddr"

	"github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	dk_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc"
	"github.com/scionproto/scion/go/pkg/cs/drkey/mock_drkey"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

var (
	ia111    = xtest.MustParseIA("1-ff00:0:111")
	ia112    = xtest.MustParseIA("1-ff00:0:112")
	tcpHost1 = netaddr.MustParseIPPort("127.0.0.1:12345")
	tcpHost2 = netaddr.MustParseIPPort("127.0.0.2:12345")
	lvl2Meta = drkey.Lvl2Meta{
		SrcIA: ia111,
		DstIA: ia112,
	}
	lvl1Raw = xtest.MustParseHexString("7f8e507aecf38c09e4cb10a0ff0cc497")
)

func TestDRKeySV(t *testing.T) {
	sv, targetResp := getSVandResp(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	serviceStore := mock_drkey.NewMockServiceEngine(ctrl)
	serviceStore.EXPECT().GetSecretValue(gomock.Any(), gomock.Any()).Return(sv, nil)

	list := map[config.HostProto]struct{}{
		{
			Host:  tcpHost1.IP(),
			Proto: drkey.SCMP,
		}: {},
	}
	server := dk_grpc.Server{
		LocalIA:            ia111,
		Engine:             serviceStore,
		AllowedSVHostProto: list,
	}
	requestPeer := &peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	peerCtx := peer.NewContext(context.Background(), requestPeer)
	request := &dkpb.SVRequest{
		ValTime:    timestamppb.Now(),
		ProtocolId: dkpb.Protocol_PROTOCOL_SCMP,
	}
	resp, err := server.SV(peerCtx, request)
	require.NoError(t, err)
	require.EqualValues(t, targetResp, resp)
}

func TestValidateASHost(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.ASHostMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				Lvl2Meta: lvl2Meta,
			},
			LocalIA:   ia112,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				Lvl2Meta: lvl2Meta,
				DstHost:  tcpHost1.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				Lvl2Meta: lvl2Meta,
				DstHost:  tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.Error,
		},
		"valid host": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.ASHostMeta{
				Lvl2Meta: lvl2Meta,
				DstHost:  tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateASHostReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateHostASReq(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.HostASMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				Lvl2Meta: lvl2Meta,
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostASMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.String(),
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"valid src": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateHostASReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateHostHostReq(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.HostHostMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				Lvl2Meta: lvl2Meta,
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
				DstHost:  tcpHost2.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostHostMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
				DstHost:  tcpHost2.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"valid src": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
				DstHost:  tcpHost2.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.NoError,
		},
		"valid dst": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostHostMeta{
				Lvl2Meta: lvl2Meta,
				SrcHost:  tcpHost1.IP().String(),
				DstHost:  tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateHostHostReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestLvl1(t *testing.T) {
	// TODO(JordiSubira): Extend this test with more cases
	grpcServer := dk_grpc.Server{}

	request := dkpb.Lvl1Request{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	_, err := grpcServer.Lvl1(ctx, &request)
	require.Error(t, err)
}

func TestASHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	lvl1Key := drkey.Lvl1Key{
		SrcIA: ia111,
		DstIA: ia112,
		Epoch: drkey.NewEpoch(0, 2),
	}
	copy(lvl1Key.Key[:], lvl1Raw)
	engine := mock_drkey.NewMockServiceEngine(ctrl)
	engine.EXPECT().DeriveASHost(gomock.Any(), gomock.Any()).Return(
		drkey.ASHostKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia112,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &dkpb.ASHostRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		DstHost:    "127.0.0.1",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.ASHost(ctx, request)
	require.NoError(t, err)

	request.ProtocolId = dkpb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.ASHost(ctx, request)
	require.NoError(t, err)
}

func TestHostAS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	lvl1Key := drkey.Lvl1Key{
		SrcIA: ia111,
		DstIA: ia112,
		Epoch: drkey.NewEpoch(0, 2),
	}
	copy(lvl1Key.Key[:], lvl1Raw)
	engine := mock_drkey.NewMockServiceEngine(ctrl)
	engine.EXPECT().DeriveHostAS(gomock.Any(), gomock.Any()).Return(
		drkey.HostASKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia111,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &dkpb.HostASRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		SrcHost:    "127.0.0.1",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.HostAS(ctx, request)
	require.NoError(t, err)

	request.ProtocolId = dkpb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.HostAS(ctx, request)
	require.NoError(t, err)
}

func TestHostHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	lvl1Key := drkey.Lvl1Key{
		SrcIA: ia111,
		DstIA: ia112,
		Epoch: drkey.NewEpoch(0, 2),
	}
	copy(lvl1Key.Key[:], lvl1Raw)
	engine := mock_drkey.NewMockServiceEngine(ctrl)
	engine.EXPECT().DeriveHostHost(gomock.Any(), gomock.Any()).Return(
		drkey.HostHostKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia111,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &dkpb.HostHostRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		SrcHost:    "127.0.0.1",
		DstHost:    "127.0.0.2",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.HostHost(ctx, request)
	require.NoError(t, err)

	request.ProtocolId = dkpb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.HostHost(ctx, request)
	require.NoError(t, err)
}

func getSVandResp(t *testing.T) (drkey.SV, *dkpb.SVResponse) {
	k := xtest.MustParseHexString("d29d00c39398b7588c0d31a4ffc77841")

	sv := drkey.SV{
		Epoch:   drkey.NewEpoch(0, 1),
		ProtoId: drkey.SCMP,
	}
	copy(sv.Key[:], k)

	targetResp := &dkpb.SVResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}
	return sv, targetResp
}
