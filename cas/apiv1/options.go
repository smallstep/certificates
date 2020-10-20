package apiv1

import (
	"crypto"
	"crypto/x509"

	"github.com/pkg/errors"
)

// Options represents the configuration options used to select and configure the
// CertificateAuthorityService (CAS) to use.
type Options struct {
	// The type of the CAS to use.
	Type string `json:"type"`

	// Path to the credentials file used in CloudCAS
	CredentialsFile string `json:"credentialsFile"`

	// CertificateAuthority reference. In CloudCAS the format is
	// `projects/*/locations/*/certificateAuthorities/*`.
	CertificateAuthority string `json:"certificateAuthority"`

	// Issuer and signer are the issuer certificate and signer used in SoftCAS.
	// They are configured in ca.json crt and key properties.
	Issuer *x509.Certificate `json:"-"`
	Signer crypto.Signer     `json:"-"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	var typ Type
	if o == nil {
		typ = Type(SoftCAS)
	} else {
		typ = Type(o.Type)
	}
	// Check that the type can be loaded.
	if _, ok := LoadCertificateAuthorityServiceNewFunc(typ); !ok {
		return errors.Errorf("unsupported cas type %s", typ)
	}
	return nil
}

// Is returns if the options have the given type.
func (o *Options) Is(t Type) bool {
	if o == nil {
		return t.String() == SoftCAS
	}
	return Type(o.Type).String() == t.String()
}
