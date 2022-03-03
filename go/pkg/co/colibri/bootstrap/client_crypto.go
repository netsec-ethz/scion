package bootstrap

import (
	"context"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/crypto"
	pb "github.com/scionproto/scion/go/pkg/proto/colibri"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
)

// type AsymServerProvider interface {
// 	GenerateKeyPair() ([]byte, []byte, error)
// 	Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
// 		associatedData ...[]byte) (DRKeyReq, error)
// 	EncryptAndSign(key drkey.DRKey) (*cryptopb.SignedMessage, error)
// }

// ClientCryptoProvider defines the crypto interface for the
// bootstrap client.
type ClientCryptoProvider interface {
	GenerateKeyPair() ([]byte, []byte, error)
	Sign(ctx context.Context, request DRKeyReq) (*pb.DRKeyRequest, error)
	VerifyDecrypt(ctx context.Context, privKey []byte, targetIA addr.IA,
		resp *pb.DRKeyResponse) (*drkey.Lvl2Key, error)
}

var _ ClientCryptoProvider = CryptoProvider{}

type CryptoProvider struct {
	// TODO(JordiSubira): Allow the crypto provider to dynamically load trust material.
	LocalIA   addr.IA
	LocalHost addr.HostAddr
	Signer    trust.Signer
	TRCs      []cppki.SignedTRC
}

// GenerateKeyPair generates a public/private key pair to be used in
// public encryption scheme.
func (p CryptoProvider) GenerateKeyPair() ([]byte, []byte, error) {
	return crypto.GenKeyPair()
}

// Sign signs a DRKey request and returns the protobuf request.
func (p CryptoProvider) Sign(ctx context.Context, request DRKeyReq) (*pb.DRKeyRequest, error) {
	pbReqBody, err := drkeyReqToPb(request)
	if err != nil {
		return nil, err
	}
	rawBody, err := proto.Marshal(pbReqBody)
	if err != nil {
		return nil, err
	}
	signedMsg, err := p.Signer.Sign(ctx, rawBody)
	if err != nil {
		return nil, err
	}
	chain := p.Signer.Chain
	pbChain := &cppb.Chain{
		AsCert: chain[0].Raw,
		CaCert: chain[1].Raw,
	}
	segs := make([]*pb.ReservationID, len(request.SegmentRsvs))
	for i, id := range request.SegmentRsvs {
		segs[i] = translate.PBufID(&id)
	}
	return &pb.DRKeyRequest{
		Chain:          pbChain,
		SignedRequest:  signedMsg,
		Segments:       segs,
		CurrentSegment: 0,
	}, nil
}

func drkeyReqToPb(request DRKeyReq) (*pb.DRKeyRequestBody, error) {
	valTime, err := ptypes.TimestampProto(request.ValTime)
	if err != nil {
		return nil, serrors.WrapStr("invalid valTime from request", err)
	}

	return &pb.DRKeyRequestBody{
		ValTime:   valTime,
		EphPubkey: request.EphPubkey,
	}, nil
}

// VerifyDecrypt verifies the protobuf response and, if successful,
// it decrypts the payload that contains the DRKey.
func (p CryptoProvider) VerifyDecrypt(ctx context.Context, privKey []byte,
	targetIA addr.IA, resp *pb.DRKeyResponse) (*drkey.Lvl2Key, error) {
	rawCerts := [][]byte{
		resp.Chain.AsCert,
		resp.Chain.CaCert,
	}
	asCert, err := crypto.VerifyPeerCertificate(targetIA, rawCerts, p.TRCs)
	if err != nil {
		return nil, serrors.WrapStr("verifying chain", err)
	}
	signedMsg, err := signed.Verify(resp.SignedResponse, asCert.PublicKey)
	if err != nil {
		return nil, serrors.WrapStr("verifying message", err)
	}

	// extract EphPubKey and cipher and decrypt
	var respBody pb.DRKeyResponseBody
	err = proto.Unmarshal(signedMsg.Body, &respBody)
	if err != nil {
		return nil, serrors.WrapStr("parsing response body", err)
	}

	rawResp, err := crypto.Decrypt(respBody.Cipher, respBody.Nonce, respBody.EphPubkey, privKey)
	if err != nil {
		return nil, serrors.WrapStr("decrypting response", err)
	}

	var pbResp pb.ASHostResponse
	err = proto.Unmarshal(rawResp, &pbResp)
	if err != nil {
		return nil, serrors.WrapStr("parsing raw key", err)
	}
	return pbASHostToKey(p.LocalIA, targetIA, p.LocalHost, &pbResp)
}

func pbASHostToKey(localIA addr.IA, targetIA addr.IA,
	localHost addr.HostAddr, rep *pb.ASHostResponse) (*drkey.Lvl2Key, error) {
	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}

	return &drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  drkey.AS2Host,
			Protocol: "colibri",
			Epoch:    epoch,
			SrcIA:    targetIA,
			DstIA:    localIA,
			DstHost:  localHost,
		},
		Key: rep.Key,
	}, nil
}

// FakeCryptoProvider is used to bypass authentication for messages.
// This is not to be used in production but to be used in testing;
// it simplifies testing/debugging.
type FakeCryptoProvider struct {
	LocalIA   addr.IA
	LocalHost addr.HostAddr
}

func (p FakeCryptoProvider) GenerateKeyPair() ([]byte, []byte, error) {
	return crypto.GenKeyPair()
}

func (p FakeCryptoProvider) Sign(ctx context.Context, request DRKeyReq) (*pb.DRKeyRequest, error) {
	pbReqBody, err := drkeyReqToPb(request)
	if err != nil {
		return nil, err
	}
	rawBody, err := proto.Marshal(pbReqBody)
	if err != nil {
		return nil, err
	}

	rawHdrAndBody, err := proto.Marshal(&cryptopb.HeaderAndBodyInternal{
		Body: rawBody,
	})
	if err != nil {
		return nil, serrors.WrapStr("packing signature input", err)
	}
	signedMsg := &cryptopb.SignedMessage{
		HeaderAndBody: rawHdrAndBody,
	}
	segs := make([]*pb.ReservationID, len(request.SegmentRsvs))
	for i, id := range request.SegmentRsvs {
		segs[i] = translate.PBufID(&id)
	}
	return &pb.DRKeyRequest{
		SignedRequest:  signedMsg,
		Segments:       segs,
		CurrentSegment: 0,
	}, nil
}

func (p FakeCryptoProvider) VerifyDecrypt(ctx context.Context, privKey []byte,
	targetIA addr.IA, resp *pb.DRKeyResponse) (*drkey.Lvl2Key, error) {

	body, err := signed.ExtractUnverifiedBody(resp.SignedResponse)
	if err != nil {
		return nil, serrors.WrapStr("verifying message", err)
	}

	// extract EphPubKey and cipher and decrypt
	var respBody pb.DRKeyResponseBody
	err = proto.Unmarshal(body, &respBody)
	if err != nil {
		return nil, serrors.WrapStr("parsing response body", err)
	}

	rawResp, err := crypto.Decrypt(respBody.Cipher, respBody.Nonce, respBody.EphPubkey, privKey)
	if err != nil {
		return nil, serrors.WrapStr("decrypting response", err)
	}
	var pbResp pb.ASHostResponse
	err = proto.Unmarshal(rawResp, &pbResp)
	if err != nil {
		return nil, serrors.WrapStr("parsing raw key", err)
	}
	return pbASHostToKey(p.LocalIA, targetIA, p.LocalHost, &pbResp)
}
