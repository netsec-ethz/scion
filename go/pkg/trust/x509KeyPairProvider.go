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

package trust

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

type X509KeyPairProvider struct {
	IA     addr.IA
	DB     DB
	Loader KeyRing
}

var _ X509KeyPairLoader = (*X509KeyPairProvider)(nil)

func (p X509KeyPairProvider) LoadX509KeyPair(ctx context.Context, extKeyUsage x509.ExtKeyUsage) (
	*tls.Certificate, error) {
	keys, err := p.Loader.PrivateKeys(ctx)
	if err != nil {
		log.Error("Error getting keys", "err", err)
		return nil, err
	}
	if len(keys) == 0 {
		log.Error("No available keys")
		return nil, serrors.New("no private key found")
	}

	trcs, _, err := activeTRCs(ctx, p.DB, p.IA.ISD())
	if err != nil {
		return nil, serrors.WrapStr("loading TRCs", err)
	}

	var bestChain []*x509.Certificate
	var bestKey crypto.Signer
	var bestExpiry time.Time
	for _, key := range keys {
		cert, expiry, err := p.bestKeyPair(ctx, trcs, extKeyUsage, key)
		if err != nil {
			log.Error("Error getting best key pair", "err", err)
			return nil, err
		}
		if cert == nil {
			continue
		}
		if bestChain != nil && bestExpiry.After(expiry) {
			continue
		}
		bestChain = cert
		bestKey = key
		bestExpiry = expiry
	}
	if bestChain == nil {
		log.Error("No certificate chain found for DRKey")
		return nil, serrors.New("no certificate found for DRKey gRPC")
	}
	certificate := make([][]byte, len(bestChain))
	for i := range bestChain {
		certificate[i] = bestChain[i].Raw
	}
	return &tls.Certificate{
		Certificate: certificate,
		PrivateKey:  bestKey,
		Leaf:        bestChain[0],
	}, nil
}

func (p X509KeyPairProvider) bestKeyPair(ctx context.Context, trcs []cppki.SignedTRC,
	extKeyUsage x509.ExtKeyUsage, signer crypto.Signer) ([]*x509.Certificate, time.Time, error) {
	skid, err := cppki.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, time.Time{}, nil
	}
	chains, err := p.DB.Chains(ctx, ChainQuery{
		IA:           p.IA,
		SubjectKeyID: skid,
		Date:         time.Now(),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	chain := bestEKUChain(&trcs[0].TRC, chains, extKeyUsage)
	if chain == nil && len(trcs) == 1 {
		return nil, time.Time{}, nil
	}
	var inGrace bool
	// Attempt to find a chain that is verifiable only in grace period. If we
	// have not found a chain yet.
	if chain == nil && len(trcs) == 2 {
		chain = bestEKUChain(&trcs[1].TRC, chains, extKeyUsage)
		if chain == nil {
			return nil, time.Time{}, nil
		}
		inGrace = true
	}
	expiry := min(chain[0].NotAfter, trcs[0].TRC.Validity.NotAfter)
	if inGrace {
		expiry = min(chain[0].NotAfter, trcs[0].TRC.GracePeriodEnd())
	}
	return chain, expiry, nil
}

func bestEKUChain(trc *cppki.TRC, chains [][]*x509.Certificate,
	extKeyUsage x509.ExtKeyUsage) []*x509.Certificate {
	opts := cppki.VerifyOptions{TRC: []*cppki.TRC{trc}}
	var best []*x509.Certificate
	for _, chain := range chains {
		if err := cppki.VerifyChain(chain, opts); err != nil {
			continue
		}
		if err := verifyExtendedKeyUsage(chain[0], extKeyUsage); err != nil {
			continue
		}
		if len(best) > 0 && chain[0].NotAfter.Before(best[0].NotAfter) {
			continue
		}
		best = chain
	}
	return best
}
