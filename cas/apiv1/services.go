package apiv1

// CertificateAuthorityService is the interface implemented to support external
// certificate authorities.
type CertificateAuthorityService interface {
	CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
	RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
	RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}

// Type represents the KMS type used.
type Type string

//
const (
	// DefaultCAS is a CertificateAuthorityService using software.
	DefaultCAS = ""
	// SoftCAS is a CertificateAuthorityService using software.
	SoftCAS = "softcas"
	// CloudCAS is a CertificateAuthorityService using Google Cloud CAS.
	CloudCAS = "cloudcas"
)
