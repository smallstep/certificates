package authority

import (
	"net"
	"reflect"
	"time"

	"github.com/pkg/errors"
	x509 "github.com/smallstep/cli/pkg/x509"
)

// certClaim interface is implemented by types used to validate specific claims in a
// certificate request.
type certClaim interface {
	Valid(crt *x509.Certificate) error
}

// ValidateClaims returns nil if all the claims are validated, it will return
// the first error if a claim fails.
func validateClaims(crt *x509.Certificate, claims []certClaim) (err error) {
	for _, c := range claims {
		if err = c.Valid(crt); err != nil {
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
func (c *commonNameClaim) Valid(crt *x509.Certificate) error {
	if crt.Subject.CommonName == "" {
		return errors.New("common name cannot be empty")
	}
	if crt.Subject.CommonName != c.name {
		return errors.Errorf("common name claim failed - got %s, want %s", crt.Subject.CommonName, c.name)
	}
	return nil
}

type dnsNamesClaim struct {
	names []string
}

// Valid checks that certificate request common name matches the one configured.
func (c *dnsNamesClaim) Valid(crt *x509.Certificate) error {
	tokMap := make(map[string]int)
	for _, e := range c.names {
		tokMap[e] = 1
	}
	crtMap := make(map[string]int)
	for _, e := range crt.DNSNames {
		crtMap[e] = 1
	}
	if !reflect.DeepEqual(tokMap, crtMap) {
		return errors.Errorf("DNS names claim failed - got %s, want %s", crt.DNSNames, c.names)
	}
	return nil
}

type ipAddressesClaim struct {
	ips []net.IP
}

// Valid checks that certificate request common name matches the one configured.
func (c *ipAddressesClaim) Valid(crt *x509.Certificate) error {
	tokMap := make(map[string]int)
	for _, e := range c.ips {
		tokMap[e.String()] = 1
	}
	crtMap := make(map[string]int)
	for _, e := range crt.IPAddresses {
		crtMap[e.String()] = 1
	}
	if !reflect.DeepEqual(tokMap, crtMap) {
		return errors.Errorf("IP Addresses claim failed - got %v, want %v", crt.IPAddresses, c.ips)
	}
	return nil
}

// certTemporalClaim validates the certificate temporal validity settings.
type certTemporalClaim struct {
	min time.Duration
	max time.Duration
}

// Validate validates the certificate temporal validity settings.
func (ctc *certTemporalClaim) Valid(crt *x509.Certificate) error {
	var (
		na  = crt.NotAfter
		nb  = crt.NotBefore
		d   = na.Sub(nb)
		now = time.Now()
	)

	if na.Before(now) {
		return errors.Errorf("NotAfter: %v cannot be in the past", na)
	}
	if na.Before(nb) {
		return errors.Errorf("NotAfter: %v cannot be before NotBefore: %v", na, nb)
	}
	if d < ctc.min {
		return errors.Errorf("requested duration of %v is less than the authorized minimum certificate duration of %v",
			d, ctc.min)
	}
	if d > ctc.max {
		return errors.Errorf("requested duration of %v is more than the authorized maximum certificate duration of %v",
			d, ctc.max)
	}
	return nil
}
