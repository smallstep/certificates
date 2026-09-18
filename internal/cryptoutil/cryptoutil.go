// Package cryptoutil provides small helpers for inspecting and encoding the
// key and certificate types used across the CA.
package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.step.sm/crypto/mldsa"
)

// IsSupportedPublicKey reports whether pub is a public key type that the CA
// knows how to work with. Anything else, including a nil key, is rejected.
func IsSupportedPublicKey(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *mldsa.PublicKey:
		return true
	default:
		return false
	}
}

// IsSupportedPrivateKey reports whether priv is a private key type that the CA
// knows how to work with. Anything else, including a nil key, is rejected.
//
// Note that keys living outside the process, like the ones backed by a KMS,
// are not reported as supported here; they only satisfy crypto.Signer.
func IsSupportedPrivateKey(priv crypto.PrivateKey) bool {
	switch priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *mldsa.PrivateKey:
		return true
	default:
		return false
	}
}

// PEMEncode encodes a key, a certificate or a certificate request using PEM.
//
// Public keys are marshaled using PKIX and private keys using PKCS #8, so the
// resulting blocks are always "PUBLIC KEY" and "PRIVATE KEY"; the legacy
// "RSA PRIVATE KEY" and "EC PRIVATE KEY" forms are never produced. Certificates
// and certificate requests are encoded from their raw DER bytes, which means
// they must have been parsed or created beforehand.
func PEMEncode(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *mldsa.PublicKey:
		b, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling public key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}), nil
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *mldsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}), nil
	case *x509.Certificate:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: k.Raw,
		}), nil
	case *x509.CertificateRequest:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: k.Raw,
		}), nil
	default:
		return nil, fmt.Errorf("error PEM encoding: unsupported type %T", key)
	}
}
