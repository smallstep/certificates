package scep

import (
	"context"
	"crypto"
	"crypto/x509"
)

// Service is a wrapper for a crypto.Decrypter and crypto.Signer for
// decrypting SCEP requests and signing certificates in response to
// SCEP certificate requests.
type Service struct {
	roots                []*x509.Certificate
	intermediates        []*x509.Certificate
	signerCertificate    *x509.Certificate
	signer               crypto.Signer
	defaultDecrypter     crypto.Decrypter
	scepProvisionerNames []string
}

// NewService returns a new Service type.
func NewService(_ context.Context, opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &Service{
		roots:                opts.Roots,
		intermediates:        opts.Intermediates,
		signerCertificate:    opts.SignerCert,
		signer:               opts.Signer,
		defaultDecrypter:     opts.Decrypter,
		scepProvisionerNames: opts.SCEPProvisionerNames,
	}, nil
}

func (s *Service) UpdateProvisioners(scepProvisionerNames []string) {
	s.scepProvisionerNames = scepProvisionerNames
}
