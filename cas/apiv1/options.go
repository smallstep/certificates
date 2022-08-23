package apiv1

import (
	"crypto"
	"crypto/x509"
	"encoding/json"

	"github.com/pkg/errors"

	"go.step.sm/crypto/kms"
)

// Options represents the configuration options used to select and configure the
// CertificateAuthorityService (CAS) to use.
type Options struct {
	// AuthorityID is the the id oc the current authority. This is used on
	// StepCAS to add information about the origin of a certificate.
	AuthorityID string `json:"-"`

	// The type of the CAS to use.
	Type string `json:"type"`

	// CertificateAuthority reference:
	// In StepCAS the value is the CA url, e.g., "https://ca.smallstep.com:9000".
	// In CloudCAS the format is "projects/*/locations/*/certificateAuthorities/*".
	// In VaultCAS the value is the url, e.g., "https://vault.smallstep.com".
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	// CertificateAuthorityFingerprint is the root fingerprint used to
	// authenticate the connection to the CA when using StepCAS.
	CertificateAuthorityFingerprint string `json:"certificateAuthorityFingerprint,omitempty"`

	// CertificateIssuer contains the configuration used in StepCAS.
	CertificateIssuer *CertificateIssuer `json:"certificateIssuer,omitempty"`

	// Path to the credentials file used in CloudCAS. If not defined the default
	// authentication mechanism provided by Google SDK will be used. See
	// https://cloud.google.com/docs/authentication.
	CredentialsFile string `json:"credentialsFile,omitempty"`

	// CertificateChain contains the issuer certificate, along with any other
	// bundled certificates to be returned in the chain to consumers. It is used
	// used in SoftCAS and it is configured in the crt property of the ca.json.
	CertificateChain []*x509.Certificate `json:"-"`

	// Signer is the private key or a KMS signer for the issuer certificate. It
	// is used in SoftCAS and it is configured in the key property of the
	// ca.json.
	Signer crypto.Signer `json:"-"`

	// CertificateSigner combines CertificateChain and Signer in a callback that
	// returns the chain of certificate and signer used to sign X.509
	// certificates in SoftCAS.
	CertificateSigner func() ([]*x509.Certificate, crypto.Signer, error) `json:"-"`

	// IsCreator is set to true when we're creating a certificate authority. It
	// is used to skip some validations when initializing a
	// CertificateAuthority. This option is used on SoftCAS and CloudCAS.
	IsCreator bool `json:"-"`

	// IsCAGetter is set to true when we're just using the
	// CertificateAuthorityGetter interface to retrieve the root certificate. It
	// is used to skip some validations when initializing a
	// CertificateAuthority. This option is used on StepCAS.
	IsCAGetter bool `json:"-"`

	// KeyManager is the KMS used to generate keys in SoftCAS.
	KeyManager kms.KeyManager `json:"-"`

	// Project, Location, CaPool and GCSBucket are parameters used in CloudCAS
	// to create a new certificate authority. If a CaPool does not exist it will
	// be created. GCSBucket is optional, if not provided GCloud will create a
	// managed bucket.
	Project    string `json:"-"`
	Location   string `json:"-"`
	CaPool     string `json:"-"`
	CaPoolTier string `json:"-"`
	GCSBucket  string `json:"-"`

	// Generic structure to configure any CAS
	Config json.RawMessage `json:"config,omitempty"`
}

// CertificateIssuer contains the properties used to use the StepCAS certificate
// authority service.
type CertificateIssuer struct {
	Type        string `json:"type"`
	Provisioner string `json:"provisioner,omitempty"`
	Certificate string `json:"crt,omitempty"`
	Key         string `json:"key,omitempty"`
	Password    string `json:"password,omitempty"`
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
