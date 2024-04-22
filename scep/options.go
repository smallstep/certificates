package scep

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

type Options struct {
	// Roots contains the (federated) CA roots certificate(s)
	Roots []*x509.Certificate `json:"-"`
	// Intermediates points issuer certificate, along with any other bundled certificates
	// to be returned in the chain for consumers.
	Intermediates []*x509.Certificate `json:"-"`
	// SignerCert points to the certificate of the CA signer. It usually is the same as the
	// first certificate in the CertificateChain.
	SignerCert *x509.Certificate `json:"-"`
	// Signer signs CSRs in SCEP. Configured in the ca.json key property.
	Signer crypto.Signer `json:"-"`
	// Decrypter decrypts encrypted SCEP messages. Configured in the ca.json key property.
	Decrypter crypto.Decrypter `json:"-"`
	// DecrypterCert points to the certificate of the CA decrypter.
	DecrypterCert *x509.Certificate `json:"-"`
	// SCEPProvisionerNames contains the currently configured SCEP provioner names. These
	// are used to be able to load the provisioners when the SCEP authority is being
	// validated.
	SCEPProvisionerNames []string
}

type comparablePublicKey interface {
	Equal(crypto.PublicKey) bool
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	switch {
	case len(o.Intermediates) == 0:
		return errors.New("no intermediate certificate available for SCEP authority")
	case o.SignerCert == nil:
		return errors.New("no signer certificate available for SCEP authority")
	}

	// the signer is optional, but if it's set, its public key must match the signer
	// certificate public key.
	if o.Signer != nil {
		// check if the signer (intermediate CA) certificate has the same public key as
		// the signer. According to the RFC it seems valid to have different keys for
		// the intermediate and the CA signing new certificates, so this might change
		// in the future.
		signerPublicKey := o.Signer.Public().(comparablePublicKey)
		if !signerPublicKey.Equal(o.SignerCert.PublicKey) {
			return errors.New("mismatch between signer certificate and public key")
		}
	}

	// decrypter can be nil in case a signing only key is used; validation complete.
	if o.Decrypter == nil {
		return nil
	}

	// If a decrypter is available, check that it's backed by an RSA key. According to the
	// RFC: https://tools.ietf.org/html/rfc8894#section-3.1, SCEP can be used with something
	// different than RSA, but requires the encryption to be performed using the challenge
	// password in that case. An older version of specification states that only RSA is
	// supported: https://tools.ietf.org/html/draft-nourse-scep-23#section-2.1.1. Other
	// algorithms do not seem to be supported in certnanny/sscep, but it might work
	// in micromdm/scep. Currently only RSA is allowed, but it might be an option
	// to try other algorithms in the future.
	decrypterPublicKey, ok := o.Decrypter.Public().(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA keys are (currently) supported as decrypters")
	}

	// check if intermediate public key is the same as the decrypter public key.
	// In certnanny/sscep it's mentioned that the signing key can be different
	// from the decrypting (and encrypting) key. These options are only used and
	// validated when the intermediate CA is also used as the decrypter, though,
	// so they should match.
	if !decrypterPublicKey.Equal(o.SignerCert.PublicKey) {
		return errors.New("mismatch between certificate chain and decrypter public keys")
	}

	return nil
}
