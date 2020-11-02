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
	"crypto/tls"
	"log"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	pb_ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	mock_st "github.com/scionproto/scion/go/lib/drkeystorage/mock_drkeystorage"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	dk_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func dialer(creds credentials.TransportCredentials,
	drkeyServer cppb.DRKeyLvl1ServiceServer) func(context.Context, string) (net.Conn, error) {
	bufsize := 1024 * 1024
	listener := bufconn.Listen(bufsize)

	server := grpc.NewServer(grpc.Creds(creds))

	cppb.RegisterDRKeyLvl1ServiceServer(server, drkeyServer)

	go func() {
		if err := server.Serve(listener); err != nil {
			log.Fatal(err)
		}
	}()

	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}

func TestLvl1KeyFetching(t *testing.T) {
	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
	crt111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"
	key111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/cp-as.key"
	tlsCert, err := tls.LoadX509KeyPair(crt111File, key111File)
	require.NoError(t, err)
	chain, err := cppki.ReadPEMCerts(crt111File)
	_ = chain
	require.NoError(t, err)
	ia111 := xtest.MustParseIA("1-ff00:0:111")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	lvl1db := mock_st.NewMockServiceStore(ctrl)
	lvl1db.EXPECT().DeriveLvl1(gomock.Any(), gomock.Any()).Return(drkey.Lvl1Key{}, nil)

	mgrdb := mock_trust.NewMockDB(ctrl)
	mgrdb.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).AnyTimes().Return(trc, nil)
	loader := mock_trust.NewMockX509KeyPairLoader(ctrl)
	loader.EXPECT().LoadX509KeyPair().AnyTimes().Return(&tlsCert, nil)
	mgr := trust.NewTLSCryptoManager(loader, mgrdb)

	drkeyServ := &dk_grpc.DRKeyServer{
		Store: lvl1db,
	}

	serverConf := &tls.Config{
		InsecureSkipVerify:    true,
		GetCertificate:        mgr.GetCertificate,
		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
	}
	serverCreds := credentials.NewTLS(serverConf)

	clientConf := &tls.Config{
		InsecureSkipVerify:    true,
		GetClientCertificate:  mgr.GetClientCertificate,
		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
	}
	clientCreds := trust.NewClientCredentials(clientConf)

	conn, err := grpc.DialContext(context.Background(),
		"1-ff00:0:111",
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithContextDialer(dialer(serverCreds, drkeyServ)),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := cppb.NewDRKeyLvl1ServiceClient(conn)

	lvl1req := pb_ctrl.NewLvl1Req(ia111, time.Now())
	req, err := pb_ctrl.Lvl1reqToProtoRequest(lvl1req)
	require.NoError(t, err)
	_, err = client.DRKeyLvl1(context.Background(), req)
	require.NoError(t, err)
}

// XXX(jordiSubira) TestLvl1KeyFetching below checks correct Lvl1 key exchange as from Go1.15
// which introduces VerifyConnection callback to access TLS state during handshake.

// func TestLvl1KeyFetching(t *testing.T) {
// 	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
// 	crt111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"
// 	key111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/cp-as.key"
// 	tlsCert, err := tls.LoadX509KeyPair(crt111File, key111File)
// 	require.NoError(t, err)
// 	chain, err := cppki.ReadPEMCerts(crt111File)
// 	_ = chain
// 	require.NoError(t, err)
// 	ia111 := xtest.MustParseIA("1-ff00:0:111")

// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	lvl1db := mock_st.NewMockServiceStore(ctrl)
// 	lvl1db.EXPECT().DeriveLvl1(gomock.Any(), gomock.Any()).Return(drkey.Lvl1Key{}, nil)

// 	mgrdb := mock_trust.NewMockDB(ctrl)
// 	mgrdb.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).AnyTimes().Return(trc, nil)
// 	loader := mock_trust.NewMockX509KeyPairLoader(ctrl)
// 	loader.EXPECT().LoadX509KeyPair().AnyTimes().Return(&tlsCert, nil)
// 	mgr := trust.NewTLSCryptoManager(loader, mgrdb)

// 	drkeyServ := &DRKeyServer{
// 		Store: lvl1db,
// 	}

// 	serverConf := &tls.Config{
// 		InsecureSkipVerify:    true,
// 		GetCertificate:        mgr.GetCertificate,
// 		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
// 		ClientAuth:            tls.RequireAnyClientCert,
// 	}
// 	serverCreds := credentials.NewTLS(serverConf)
// 	clientConf := &tls.Config{
// 		InsecureSkipVerify:    true,
// 		GetClientCertificate:  mgr.GetClientCertificate,
// 		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
// 		VerifyConnection:      verifyConnection,
// 	}
// 	clientCreds := credentials.NewTLS(clientConf)

// 	conn, err := grpc.DialContext(context.Background(),
// 		"1-ff00:0:112",
// 		grpc.WithTransportCredentials(clientCreds),
// 		grpc.WithContextDialer(dialer(serverCreds, drkeyServ)),
// 	)
// 	// conn, err := grpc.DialContext(context.Background(), "",
// 	// 	grpc.WithInsecure(),
// 	// 	grpc.WithContextDialer(dialer(serverCreds, drkeyServ)))
// 	require.NoError(t, err)
// 	defer conn.Close()

// 	client := cppb.NewDRKeyLvl1ServiceClient(conn)

// 	lvl1req := pb_ctrl.NewLvl1Req(ia111, time.Now())
// 	req, err := lvl1reqToProtoRequest(lvl1req)
// 	require.NoError(t, err)
// 	_, err = client.DRKeyLvl1(context.Background(), req)
// 	require.NoError(t, err)
// }

// func verifyConnection(cs tls.ConnectionState) error {
// 	serverIA, err := addr.IAFromString(cs.ServerName)
// 	if err != nil {
// 		return serrors.WrapStr("extracting IA from server name", err)
// 	}
// 	certIA, err := cppki.ExtractIA(cs.PeerCertificates[0].Subject)
// 	if err != nil {
// 		return serrors.WrapStr("extracting IA from peer cert", err)
// 	}
// 	if !serverIA.Equal(*certIA) {
// 		return serrors.New("extracted IA from cert and server IA do not match",
// 			"peer IA", certIA, "server IA", serverIA)
// 	}
// 	return nil
// }
