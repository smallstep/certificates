package stepcas

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
)

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
