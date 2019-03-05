package provisioner

import (
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
)

// SignOption is the interface used to collect all extra options used in the
// Sign method.
type SignOption interface{}

// CertificateValidator is the interface used to validate a X.509 certificate.
type CertificateValidator interface {
	SignOption
	Valid(crt *x509.Certificate) error
}

// CertificateRequestValidator is the interface used to validate a X.509
// certificate request.
type CertificateRequestValidator interface {
	SignOption
	Valid(req *x509.CertificateRequest)
}

// ProfileWithOption is the interface used to add custom options to the profile
// constructor. The options are used to modify the final certificate.
type ProfileWithOption interface {
	SignOption
	Option() x509util.WithOption
}

// emailOnlyIdentity is a CertificateRequestValidator that checks that the only
// SAN provided is the given email address.
type emailOnlyIdentity string

func (e emailOnlyIdentity) Valid(req *x509.CertificateRequest) error {
	switch {
	case len(req.DNSNames) > 0:
		return errors.New("certificate request cannot contain DNS names")
	case len(req.IPAddresses) > 0:
		return errors.New("certificate request cannot contain IP addresses")
	case len(req.URIs) > 0:
		return errors.New("certificate request cannot contain URIs")
	case len(req.EmailAddresses) == 0:
		return errors.New("certificate request does not contain any email address")
	case len(req.EmailAddresses) > 1:
		return errors.New("certificate request does not contain too many email addresses")
	case req.EmailAddresses[0] != string(e):
		return errors.New("certificate request does not contain the valid email address")
	default:
		return nil
	}
}
