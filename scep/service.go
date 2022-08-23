package scep

import (
	"context"
	"crypto"
	"crypto/x509"
)

// Service is a wrapper for crypto.Signer and crypto.Decrypter
type Service struct {
	certificateChain []*x509.Certificate
	signer           crypto.Signer
	decrypter        crypto.Decrypter
}

func NewService(ctx context.Context, opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// TODO: should this become similar to the New CertificateAuthorityService as in x509CAService?
	return &Service{
		certificateChain: opts.CertificateChain,
		signer:           opts.Signer,
		decrypter:        opts.Decrypter,
	}, nil
}
