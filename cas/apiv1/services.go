package apiv1

import (
	"crypto/x509"
	"net/http"
	"strings"
)

// CertificateAuthorityService is the interface implemented to support external
// certificate authorities.
type CertificateAuthorityService interface {
	CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
	RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
	RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}

// CertificateAuthorityCRLGenerator is an optional interface implemented by CertificateAuthorityService
// that has a method to create a CRL
type CertificateAuthorityCRLGenerator interface {
	CreateCRL(req *CreateCRLRequest) (*CreateCRLResponse, error)
}

// CertificateAuthorityGetter is an interface implemented by a
// CertificateAuthorityService that has a method to get the root certificate.
type CertificateAuthorityGetter interface {
	GetCertificateAuthority(req *GetCertificateAuthorityRequest) (*GetCertificateAuthorityResponse, error)
}

// CertificateAuthorityCreator is an interface implamented by a
// CertificateAuthorityService that has a method to create a new certificate
// authority.
type CertificateAuthorityCreator interface {
	CreateCertificateAuthority(req *CreateCertificateAuthorityRequest) (*CreateCertificateAuthorityResponse, error)
}

// SignatureAlgorithmGetter is an optional implementation in a crypto.Signer
// that returns the SignatureAlgorithm to use.
type SignatureAlgorithmGetter interface {
	SignatureAlgorithm() x509.SignatureAlgorithm
}

// Type represents the CAS type used.
type Type string

const (
	// DefaultCAS is a CertificateAuthorityService using software.
	DefaultCAS = ""
	// SoftCAS is a CertificateAuthorityService using software.
	SoftCAS = "softcas"
	// CloudCAS is a CertificateAuthorityService using Google Cloud CAS.
	CloudCAS = "cloudcas"
	// StepCAS is a CertificateAuthorityService using another step-ca instance.
	StepCAS = "stepcas"
	// VaultCAS is a CertificateAuthorityService using Hasicorp Vault PKI.
	VaultCAS = "vaultcas"
)

// String returns a string from the type. It will always return the lower case
// version of the Type, as we need a standard type to compare and use as the
// registry key.
func (t Type) String() string {
	if t == "" {
		return SoftCAS
	}
	return strings.ToLower(string(t))
}

// NotImplementedError is the type of error returned if an operation is not implemented.
type NotImplementedError struct {
	Message string
}

// Error implements the error interface.
func (e NotImplementedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "not implemented"
}

// StatusCode implements the StatusCoder interface and returns the HTTP 501
// error.
func (e NotImplementedError) StatusCode() int {
	return http.StatusNotImplemented
}

// ValidationError is the type of error returned if request is not properly
// validated.
type ValidationError struct {
	Message string
}

// NotImplementedError implements the error interface.
func (e ValidationError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "bad request"
}

// StatusCode implements the StatusCoder interface and returns the HTTP 400
// error.
func (e ValidationError) StatusCode() int {
	return http.StatusBadRequest
}
