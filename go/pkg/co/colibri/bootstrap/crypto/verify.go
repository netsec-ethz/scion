package crypto

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
)

const defaultTimeout = 5 * time.Second

var (
	errNotFound = serrors.New("not found")
	errInactive = serrors.New("inactive")
)

func VerifyPeerCertificate(targetIA addr.IA, rawCerts [][]byte,
	trcs []cppki.SignedTRC) (*x509.Certificate, error) {
	chain := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return nil, serrors.WrapStr("parsing peer certificate", err)
		}
		chain[i] = cert
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return nil, serrors.WrapStr("extracting ISD-AS from peer certificate", err)
	}
	if ia != targetIA {
		return nil, serrors.New("IA mismatch", "targetIA", targetIA, "extractedIA", ia)
	}
	// ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	// defer cancel()
	// trcs, err := activeTRCs(ctx, db, ia.I)
	// if err != nil {
	// 	return nil, serrors.WrapStr("loading TRCs", err)
	// }
	if err := verifyChain(chain, trcs); err != nil {
		return nil, serrors.WrapStr("verifying chains", err)
	}
	return chain[0], nil
}

func activeTRCs(ctx context.Context, db trust.DB, isd addr.ISD) ([]cppki.SignedTRC, error) {
	trc, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		return nil, err
	}
	if trc.IsZero() {
		return nil, errNotFound
	}
	// XXX(roosd): This could resolve newer TRCs over the network. However,
	// for every GetChains by the verifier, there should be a NotifyTRC, such
	// that should never run into this condition in the first place.
	if !trc.TRC.Validity.Contains(time.Now()) {
		return nil, errInactive
	}
	if !trc.TRC.InGracePeriod(time.Now()) {
		return []cppki.SignedTRC{trc}, nil
	}
	grace, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   trc.TRC.ID.Base,
		Serial: trc.TRC.ID.Serial - 1,
	})
	if err != nil {
		return nil, err
	}
	if grace.IsZero() {
		return nil, errNotFound
	}
	return []cppki.SignedTRC{trc, grace}, nil
}

func verifyChain(chain []*x509.Certificate, trcs []cppki.SignedTRC) error {
	var errs serrors.List
	for _, trc := range trcs {
		verifyOptions := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
		if err := cppki.VerifyChain(chain, verifyOptions); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return errs.ToError()
}
