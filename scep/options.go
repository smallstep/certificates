package scep

import (
	"crypto"
	"crypto/x509"
)

type Options struct {
	// CertificateChain is the issuer certificate, along with any other bundled certificates
	// to be returned in the chain for consumers. Configured in ca.json crt property.
	CertificateChain []*x509.Certificate
	// Signer signs CSRs in SCEP. Configured in ca.json key property.
	Signer crypto.Signer `json:"-"`
	// Decrypter decrypts encrypted SCEP messages. Configured in ca.json key property.
	Decrypter crypto.Decrypter `json:"-"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	// var typ Type
	// if o == nil {
	// 	typ = Type(SoftCAS)
	// } else {
	// 	typ = Type(o.Type)
	// }
	// // Check that the type can be loaded.
	// if _, ok := LoadCertificateAuthorityServiceNewFunc(typ); !ok {
	// 	return errors.Errorf("unsupported cas type %s", typ)
	// }
	return nil
}
