package apiv1

import (
	"crypto/x509"
	"time"
)

type CreateCertificateRequest struct {
	Template  *x509.Certificate
	Lifetime  time.Duration
	Backdate  time.Duration
	RequestID string
}
type CreateCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

type RenewCertificateRequest struct {
	Template  *x509.Certificate
	Lifetime  time.Duration
	Backdate  time.Duration
	RequestID string
}
type RenewCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

// RevokeCertificateRequest is the request used to revoke a certificate.
type RevokeCertificateRequest struct {
	Certificate *x509.Certificate
}
type RevokeCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}
