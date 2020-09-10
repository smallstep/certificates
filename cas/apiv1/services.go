package apiv1

import (
	"encoding/asn1"
	"strings"
)

var (
	oidStepRoot                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	oidStepCertificateAuthority = append(asn1.ObjectIdentifier(nil), append(oidStepRoot, 2)...)
)

// CertificateAuthorityService is the interface implemented to support external
// certificate authorities.
type CertificateAuthorityService interface {
	CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
	RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
	RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}

// Type represents the KMS type used.
type Type string

const (
	// DefaultCAS is a CertificateAuthorityService using software.
	DefaultCAS = ""
	// SoftCAS is a CertificateAuthorityService using software.
	SoftCAS = "SoftCAS"
	// CloudCAS is a CertificateAuthorityService using Google Cloud CAS.
	CloudCAS = "CloudCAS"
)

// String returns the given type as a string. All the letters will be lowercase.
func (t Type) String() string {
	if t == "" {
		return SoftCAS
	}
	for _, s := range []string{SoftCAS, CloudCAS} {
		if strings.EqualFold(s, string(t)) {
			return s
		}
	}
	return string(t)
}
