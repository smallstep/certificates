package scep

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

type Options struct {
	// CertificateChain is the issuer certificate, along with any other bundled certificates
	// to be returned in the chain for consumers. Configured in the ca.json crt property.
	CertificateChain []*x509.Certificate
	// Signer signs CSRs in SCEP. Configured in the ca.json key property.
	Signer crypto.Signer `json:"-"`
	// Decrypter decrypts encrypted SCEP messages. Configured in the ca.json key property.
	Decrypter crypto.Decrypter `json:"-"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	if o.CertificateChain == nil {
		return errors.New("certificate chain not configured correctly")
	}

	if len(o.CertificateChain) < 1 {
		return errors.New("certificate chain should at least have one certificate")
	}

	// According to the RFC: https://tools.ietf.org/html/rfc8894#section-3.1, SCEP
	// can be used with something different than RSA, but requires the encryption
	// to be performed using the challenge password. An older version of specification
	// states that only RSA is supported: https://tools.ietf.org/html/draft-nourse-scep-23#section-2.1.1
	// Other algorithms than RSA do not seem to be supported in certnanny/sscep, but it might work
	// in micromdm/scep. Currently only RSA is allowed, but it might be an option
	// to try other algorithms in the future.
	intermediate := o.CertificateChain[0]
	if intermediate.PublicKeyAlgorithm != x509.RSA {
		return errors.New("only the RSA algorithm is (currently) supported")
	}

	// TODO: add checks for key usage?

	signerPublicKey, ok := o.Signer.Public().(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA public keys are (currently) supported as signers")
	}

	// check if the intermediate ca certificate has the same public key as the signer.
	// According to the RFC it seems valid to have different keys for the intermediate
	// and the CA signing new certificates, so this might change in the future.
	if !signerPublicKey.Equal(intermediate.PublicKey) {
		return errors.New("mismatch between certificate chain and signer public keys")
	}

	decrypterPublicKey, ok := o.Decrypter.Public().(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA public keys are (currently) supported as decrypters")
	}

	// check if intermediate public key is the same as the decrypter public key.
	// In certnanny/sscep it's mentioned that the signing key can be different
	// from the decrypting (and encrypting) key. Currently that's not supported.
	if !decrypterPublicKey.Equal(intermediate.PublicKey) {
		return errors.New("mismatch between certificate chain and decrypter public keys")
	}

	return nil
}
