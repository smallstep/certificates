package stepcas

import (
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
)

type raInfo struct {
	AuthorityID     string `json:"authorityId,omitempty"`
	ProvisionerID   string `json:"provisionerId"`
	ProvisionerType string `json:"provisionerType"`
	ProvisionerName string `json:"provisionerName"`
}

type stepIssuer interface {
	SignToken(subject string, sans []string, info *raInfo) (string, error)
	RevokeToken(subject string) (string, error)
	Lifetime(d time.Duration) time.Duration
}

// newStepIssuer returns the configured step issuer.
func newStepIssuer(caURL *url.URL, client *ca.Client, iss *apiv1.CertificateIssuer) (stepIssuer, error) {
	if err := validateCertificateIssuer(iss); err != nil {
		return nil, err
	}

	switch strings.ToLower(iss.Type) {
	case "x5c":
		return newX5CIssuer(caURL, iss)
	case "jwk":
		return newJWKIssuer(caURL, client, iss)
	default:
		return nil, errors.Errorf("stepCAS `certificateIssuer.type` %s is not supported", iss.Type)
	}
}

// validateCertificateIssuer validates the configuration of the certificate
// issuer.
func validateCertificateIssuer(iss *apiv1.CertificateIssuer) error {
	switch {
	case iss == nil:
		return errors.New("stepCAS 'certificateIssuer' cannot be nil")
	case iss.Type == "":
		return errors.New("stepCAS `certificateIssuer.type` cannot be empty")
	}

	switch strings.ToLower(iss.Type) {
	case "x5c":
		return validateX5CIssuer(iss)
	case "jwk":
		return validateJWKIssuer(iss)
	default:
		return errors.Errorf("stepCAS `certificateIssuer.type` %s is not supported", iss.Type)
	}
}

// validateX5CIssuer validates the configuration of x5c issuer.
func validateX5CIssuer(iss *apiv1.CertificateIssuer) error {
	switch {
	case iss.Certificate == "":
		return errors.New("stepCAS `certificateIssuer.crt` cannot be empty")
	case iss.Key == "":
		return errors.New("stepCAS `certificateIssuer.key` cannot be empty")
	case iss.Provisioner == "":
		return errors.New("stepCAS `certificateIssuer.provisioner` cannot be empty")
	default:
		return nil
	}
}

// validateJWKIssuer validates the configuration of jwk issuer. If the key is
// not given, then it will download it from the CA. If the password is not set
// it will be prompted.
func validateJWKIssuer(iss *apiv1.CertificateIssuer) error {
	switch {
	case iss.Provisioner == "":
		return errors.New("stepCAS `certificateIssuer.provisioner` cannot be empty")
	default:
		return nil
	}
}
