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
	"github.com/scionproto/scion/go/pkg/trust"
)

// type AsymServerProvider interface {
// 	GenerateKeyPair() ([]byte, []byte, error)
// 	Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
// 		associatedData ...[]byte) (DRKeyReq, error)
// 	EncryptAndSign(key drkey.DRKey) (*cryptopb.SignedMessage, error)
// }

type ClientCryptoProvider interface {
	GenerateKeyPair() ([]byte, []byte, error)
	Sign(ctx context.Context, request DRKeyReq) (*pb.DRKeyRequest, error)
	VerifyDecrypt(ctx context.Context, privKey []byte, targetIA addr.IA,
		resp *pb.DRKeyResponse) (*drkey.Lvl2Key, error)
}

var _ ClientCryptoProvider = cryptoProvider{}

type cryptoProvider struct {
	localIA addr.IA
	signer  trust.Signer
	db      trust.DB
}

func (p cryptoProvider) GenerateKeyPair() ([]byte, []byte, error) {
	return crypto.GenKeyPair()
}

func (p cryptoProvider) Sign(ctx context.Context, request DRKeyReq) (*pb.DRKeyRequest, error) {
	pbReqBody, err := drkeyReqToPb(request)
	if err != nil {
		return nil, err
	}
	rawBody, err := proto.Marshal(pbReqBody)
	if err != nil {
		return nil, err
	}
	signedMsg, err := p.signer.Sign(ctx, rawBody)
	if err != nil {
		return nil, err
	}
	chain := p.signer.Chain
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

func (p cryptoProvider) VerifyDecrypt(ctx context.Context, privKey []byte,
	targetIA addr.IA, resp *pb.DRKeyResponse) (*drkey.Lvl2Key, error) {
	rawCerts := [][]byte{
		resp.Chain.AsCert,
		resp.Chain.CaCert,
	}
	asCert, err := crypto.VerifyPeerCertificate(targetIA, rawCerts, p.db)
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
	var pbResp pb.ASHostResponse
	err = proto.Unmarshal(rawResp, &pbResp)
	if err != nil {
		return nil, serrors.WrapStr("parsing raw key", err)
	}
	return pbASHostToKey(p.localIA, targetIA, &pbResp)
}

func pbASHostToKey(localIA addr.IA, targetIA addr.IA, rep *pb.ASHostResponse) (*drkey.Lvl2Key, error) {
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
		},
	}, nil
}
