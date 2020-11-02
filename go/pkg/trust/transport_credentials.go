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

package trust

import (
	"context"
	"crypto/tls"
	"net"

	"google.golang.org/grpc/credentials"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

// XXX(jordiSubira): ClientCredentials enables hooking a procedure to validate
// the TLS state during the client handshake. Note that the current implementation
// extends the grpc/credentials callback for TLS credentials by carrying out the
// validation after the handshake has been completed (this last using the provided
// TLS config).
// Go1.15 introduces the VerifyConnection callback within TLS Config which would
// enable hooking the procedure to validate the TLS state within the TLS client
// handshake. Therefore, if Go1.15 (or greater) is used ClientCredentials should
// be deprecated using the aforementioned alternative.

// ClientCredentials implements credentials.TransportCredentials extending
// the ClientHandshake callback
type ClientCredentials struct {
	credentials.TransportCredentials
}

// NewClientCredentials returns a new instance which embeds tlsCred, which in turn
// implements credentials.TransportCredentials interface
func NewClientCredentials(conf *tls.Config) credentials.TransportCredentials {
	return &ClientCredentials{
		credentials.NewTLS(conf),
	}
}

// ClientHandshake extends the embedded TransportCredentials callback by verifying the peer's name
// and the information provided in the certificate. Upon error the connection is closed and a
// non-temporary error is returned.
func (c *ClientCredentials) ClientHandshake(ctx context.Context, authority string,
	rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	conn, authInfo, err := c.TransportCredentials.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return nil, nil, err
	}

	tlsInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		conn.Close()
		return nil, nil, &nonTempWrapper{
			serrors.New("authInfo should be type tlsInfo and is",
				"authInfoType", authInfo.AuthType()),
		}
	}
	// XXX (jonito): In Go1.13 tls.ConnectionState.ServerName is only set
	// on ther server side. Thus, we pass authority as the serverName.
	if err = verifyConnection(tlsInfo.State, authority); err != nil {
		conn.Close()
		return nil, nil, &nonTempWrapper{
			serrors.WrapStr("verifying connection in client handshake", err),
		}
	}
	return conn, tlsInfo, nil
}

type nonTempWrapper struct {
	error
}

func (e *nonTempWrapper) Temporary() bool {
	return false
}

func verifyConnection(cs tls.ConnectionState, serverName string) error {
	serverIA, err := addr.IAFromString(serverName)
	if err != nil {
		return serrors.WrapStr("extracting IA from server name", err)
	}
	certIA, err := cppki.ExtractIA(cs.PeerCertificates[0].Subject)
	if err != nil {
		return serrors.WrapStr("extracting IA from peer cert", err)
	}
	if !serverIA.Equal(*certIA) {
		return serrors.New("extracted IA from cert and server IA do not match",
			"peer IA", certIA, "server IA", serverIA)
	}
	return nil
}
