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

package exchange

import (
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

func ValitadePeerWithCert(peer *peer.Peer, ia addr.IA) error {
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return serrors.New("auth info is not of type TLS info",
			"peer", peer, "authType", peer.AuthInfo.AuthType())
	}
	chain := tlsInfo.State.PeerCertificates
	certIA, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return serrors.WrapStr("extracting IA from peer cert", err)
	}
	if !ia.Equal(*certIA) {
		return serrors.New("peer IA from cert and requested IA do not match",
			"peer IA", certIA, "req IA", ia)
	}
	return nil
}
