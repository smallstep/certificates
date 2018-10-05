package authority

import (
	"crypto/x509"
	"net"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/api"
)

// ValidateClaims returns nil if all the claims are validated, it will return
// the first error if a claim fails.
func ValidateClaims(cr *x509.CertificateRequest, claims []api.Claim) (err error) {
	for _, c := range claims {
		if err = c.Valid(cr); err != nil {
			return err
		}
	}
	return
}

// commonNameClaim validates the common name of a certificate request.
type commonNameClaim struct {
	name string
}

// Valid checks that certificate request common name matches the one configured.
func (c *commonNameClaim) Valid(cr *x509.CertificateRequest) error {
	if cr.Subject.CommonName == "" {
		return errors.New("common name cannot be empty")
	}
	if cr.Subject.CommonName != c.name {
		return errors.Errorf("common name claim failed - got %s, want %s", cr.Subject.CommonName, c.name)
	}
	return nil
}

type dnsNamesClaim struct {
	name string
}

// Valid checks that certificate request common name matches the one configured.
func (c *dnsNamesClaim) Valid(cr *x509.CertificateRequest) error {
	if len(cr.DNSNames) == 0 {
		return nil
	}
	for _, name := range cr.DNSNames {
		if name != c.name {
			return errors.Errorf("DNS names claim failed - got %s, want %s", name, c.name)
		}
	}
	return nil
}

type ipAddressesClaim struct {
	name string
}

// Valid checks that certificate request common name matches the one configured.
func (c *ipAddressesClaim) Valid(cr *x509.CertificateRequest) error {
	if len(cr.IPAddresses) == 0 {
		return nil
	}

	// If it's an IP validate that only that ip is in IP addresses
	if requestedIP := net.ParseIP(c.name); requestedIP != nil {
		for _, ip := range cr.IPAddresses {
			if !ip.Equal(requestedIP) {
				return errors.Errorf("IP addresses claim failed - got %s, want %s", ip, requestedIP)
			}
		}
		return nil
	}

	return errors.Errorf("IP addresses claim failed - got %v, want none", cr.IPAddresses)
}
