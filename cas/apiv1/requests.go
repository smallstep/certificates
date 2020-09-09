package apiv1

import (
	"crypto"
	"crypto/x509"
	"time"
)

type CreateCertificateRequest struct {
	Template *x509.Certificate
	Issuer   *x509.Certificate
	Signer   crypto.Signer
	Lifetime time.Duration

	RequestID string
}
type CreateCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

type RenewCertificateRequest struct{}
type RenewCertificateResponse struct{}

type RevokeCertificateRequest struct{}
type RevokeCertificateResponse struct{}
