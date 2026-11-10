package est

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// Options configures the EST authority instance.
type Options struct {
	Roots         []*x509.Certificate `json:"-"`
	Intermediates []*x509.Certificate `json:"-"`
	SignerCert    *x509.Certificate   `json:"-"`
	Signer        crypto.Signer       `json:"-"`

	ESTProvisionerNames []string
}

type comparablePublicKey interface {
	Equal(crypto.PublicKey) bool
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	switch {
	case len(o.Intermediates) == 0:
		return errors.New("no intermediate certificate available for EST authority")
	case o.SignerCert == nil:
		return errors.New("no signer certificate available for EST authority")
	}

	if o.Signer != nil {
		signerPublicKey := o.Signer.Public().(comparablePublicKey)
		if !signerPublicKey.Equal(o.SignerCert.PublicKey) {
			return errors.New("mismatch between signer certificate and public key")
		}
	}

	return nil
}
