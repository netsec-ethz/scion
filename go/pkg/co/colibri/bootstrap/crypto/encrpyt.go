package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"

	"github.com/scionproto/scion/go/lib/serrors"
)

// Constants for nacl/box implementation of Curve25519xSalsa20Poly1305
const (
	NaClBoxNonceSize = 24
	NaClBoxKeySize   = 32
)

// Errors
var (
	ErrInvalidPubKeySize       = serrors.New("Invalid public key size")
	ErrInvalidPrivKeySize      = serrors.New("Invalid private key size")
	ErrUnableToGenerateKeyPair = serrors.New("Unable to generate key pair")
	ErrUnableToDecrypt         = serrors.New("Unable to decrypt message")
	ErrInvalidNonceSize        = serrors.New("Invalid nonce size")
)

// GenKeyPair generates a public/private key pair.
func GenKeyPair() ([]byte, []byte, error) {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, serrors.Wrap(ErrUnableToGenerateKeyPair, err)
	}
	return pubkey[:], privkey[:], nil
}

// Encrypt takes a message, a nonce and a public/private keypair and
// returns the encrypted and authenticated message.
// Note: Nonce must be different for each message that is encrypted with the same key.
func Encrypt(msg, nonce, pubkey, privkey []byte) ([]byte, error) {

	nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
	if err != nil {
		return nil, err
	}
	return box.Seal(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw), nil

}

// Decrypt decrypts a message for a given nonce and public/private keypair.
func Decrypt(msg, nonce, pubkey, privkey []byte) ([]byte, error) {

	nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
	if err != nil {
		return nil, err
	}
	dec, ok := box.Open(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw)
	if !ok {
		return nil, ErrUnableToDecrypt
	}
	return dec, nil
}

func prepNaClBox(nonce, pubkey, privkey []byte) (*[NaClBoxNonceSize]byte,
	*[NaClBoxKeySize]byte, *[NaClBoxKeySize]byte, error) {

	if len(nonce) != NaClBoxNonceSize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidNonceSize,
			"expected size", NaClBoxNonceSize, "actual size",
			len(nonce))
	}
	if len(pubkey) != NaClBoxKeySize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidPubKeySize,
			"expected size", NaClBoxKeySize, "actual size", len(pubkey))
	}
	if len(privkey) != NaClBoxKeySize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidPrivKeySize,
			"expected size", NaClBoxKeySize, "actual size",
			len(privkey))
	}
	var nonceRaw [NaClBoxNonceSize]byte
	var pubKeyRaw, privKeyRaw [NaClBoxKeySize]byte
	copy(nonceRaw[:], nonce)
	copy(pubKeyRaw[:], pubkey)
	copy(privKeyRaw[:], privkey)
	return &nonceRaw, &pubKeyRaw, &privKeyRaw, nil
}
