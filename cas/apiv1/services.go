package apiv1

import (
	"strings"
)

// CertificateAuthorityService is the interface implemented to support external
// certificate authorities.
type CertificateAuthorityService interface {
	CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
	RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
	RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
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

// Type represents the CAS type used.
type Type string

const (
	// DefaultCAS is a CertificateAuthorityService using software.
	DefaultCAS = ""
	// SoftCAS is a CertificateAuthorityService using software.
	SoftCAS = "softcas"
	// CloudCAS is a CertificateAuthorityService using Google Cloud CAS.
	CloudCAS = "cloudcas"
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
