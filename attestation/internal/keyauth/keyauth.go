// Package keyauth verifies the signatures over ACME key authorizations that
// device-attest-01 attestation statements carry.
package keyauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"go.step.sm/crypto/mldsa"

	"github.com/smallstep/certificates/attestation"
)

// Verify verifies that sig is a signature of the key authorization made with
// the private key of the given attestation certificate. Its errors match
// attestation.ErrInvalidEvidence.
func Verify(cert *x509.Certificate, keyAuth, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return attestation.Invalidf("unsupported elliptic curve %s", pub.Curve)
		}
		sum := sha256.Sum256(keyAuth)
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return attestation.Invalidf("failed validating signature")
		}
	case *rsa.PublicKey:
		sum := sha256.Sum256(keyAuth)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return attestation.Invalidf("failed validating signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, keyAuth, sig) {
			return attestation.Invalidf("failed validating signature")
		}
	case *mldsa.PublicKey:
		if err := mldsa.Verify(pub, keyAuth, sig, nil); err != nil {
			return attestation.Invalidf("failed validating signature")
		}
	default:
		return attestation.Invalidf("unsupported public key type %T", pub)
	}

	return nil
}
