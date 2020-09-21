package apiv1

import (
	"crypto/x509"
	"time"
)

// CreateCertificateRequest is the request used to sign a new certificate.
type CreateCertificateRequest struct {
	Template  *x509.Certificate
	Lifetime  time.Duration
	Backdate  time.Duration
	RequestID string
}

// CreateCertificateResponse is the response to a create certificate request.
type CreateCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

// RenewCertificateRequest is the request used to re-sign a certificate.
type RenewCertificateRequest struct {
	Template  *x509.Certificate
	Lifetime  time.Duration
	Backdate  time.Duration
	RequestID string
}

// RenewCertificateResponse is the response to a renew certificate request.
type RenewCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

// RevokeCertificateRequest is the request used to revoke a certificate.
type RevokeCertificateRequest struct {
	Certificate *x509.Certificate
	Reason      string
	ReasonCode  int
	RequestID   string
}

// RevokeCertificateResponse is the response to a revoke certificate request.
type RevokeCertificateResponse struct {
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

// GetCertificateAuthorityRequest is the request used to get the root
// certificate from a CAS.
type GetCertificateAuthorityRequest struct {
	Name string
}

// GetCertificateAuthorityResponse is the response that contains
// the root certificate.
type GetCertificateAuthorityResponse struct {
	RootCertificate *x509.Certificate
}
