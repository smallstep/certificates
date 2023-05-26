package scep

import (
	"context"
	"crypto"
	"crypto/x509"
)

// Service is a wrapper for crypto.Signer and crypto.Decrypter
type Service struct {
	certificateChain            []*x509.Certificate
	signerCertificate           *x509.Certificate
	signer                      crypto.Signer
	defaultDecrypterCertificate *x509.Certificate
	defaultDecrypter            crypto.Decrypter
}

// NewService returns a new Service type.
func NewService(_ context.Context, opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// TODO: should this become similar to the New CertificateAuthorityService as in x509CAService?
	return &Service{
		certificateChain:            opts.CertificateChain,
		signerCertificate:           opts.SignerCert,
		signer:                      opts.Signer,
		defaultDecrypterCertificate: opts.DecrypterCert,
		defaultDecrypter:            opts.Decrypter,
	}, nil
}
