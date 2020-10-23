package apiv1

import (
	"crypto"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms"
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

	// IsCreator is set to true when we're creating a certificate authority. Is
	// used to skip some validations when initializing a CertificateAuthority.
	IsCreator bool `json:"-"`

	// KeyManager is the KMS used to generate keys in SoftCAS.
	KeyManager kms.KeyManager `json:"-"`

	// Project and Location are parameters used in CloudCAS to create a new
	// certificate authority.
	Project  string `json:"-"`
	Location string `json:"-"`
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
