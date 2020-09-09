package apiv1

import (
	"strings"

	"github.com/pkg/errors"
)

// Options represents the configuration options used to select and configure the
// CertificateAuthorityService (CAS) to use.
type Options struct {
	// The type of the CAS to use.
	Type string `json:"type"`

	// Path to the credentials file used in CloudCAS
	CredentialsFile string `json:"credentialsFile"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}

	switch Type(strings.ToLower(o.Type)) {
	case DefaultCAS, SoftCAS, CloudCAS:
	default:
		return errors.Errorf("unsupported kms type %s", o.Type)
	}

	return nil
}
