package dtls

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type namedCurve uint16

type namedCurveKeypair struct {
	curve      namedCurve
	publicKey  []byte
	privateKey []byte
}

// Public satisfies part of crypto.Signer and crypto.Decrypter interfaces
func (n *namedCurveKeypair) Public() crypto.PublicKey {
	return n.publicKey
}

// Sign satisfies part of the crypto.Signer interface
func (n *namedCurveKeypair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return n.Sign(rand, digest, opts)
}

// Decrypt satisfies part of the crypto.Decrypter interface
func (n *namedCurveKeypair) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	return n.Decrypt(rand, ciphertext, opts)
}

const (
	namedCurveP256   namedCurve = 0x0017
	namedCurveP384   namedCurve = 0x0018
	namedCurveX25519 namedCurve = 0x001d
)

var namedCurves = map[namedCurve]bool{
	namedCurveX25519: true,
	namedCurveP256:   true,
	namedCurveP384:   true,
}

func generateKeypair(c namedCurve) (*namedCurveKeypair, error) {
	switch c {
	case namedCurveX25519:
		tmp := make([]byte, 32)
		if _, err := rand.Read(tmp); err != nil {
			return nil, err
		}

		var public, private [32]byte
		copy(private[:], tmp)

		curve25519.ScalarBaseMult(&public, &private)
		return &namedCurveKeypair{namedCurveX25519, public[:], private[:]}, nil
	case namedCurveP256:
		return ellipticCurveKeypair(namedCurveP256, elliptic.P256(), elliptic.P256())
	case namedCurveP384:
		return ellipticCurveKeypair(namedCurveP384, elliptic.P384(), elliptic.P384())
	}
	return nil, errInvalidNamedCurve
}

func ellipticCurveKeypair(nc namedCurve, c1, c2 elliptic.Curve) (*namedCurveKeypair, error) {
	privateKey, x, y, err := elliptic.GenerateKey(c1, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &namedCurveKeypair{nc, elliptic.Marshal(c2, x, y), privateKey}, nil
}
