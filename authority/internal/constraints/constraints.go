package constraints

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

var oidExtensionNameConstraints = []int{2, 5, 29, 30}

// ConstraintError is the typed error that will be returned if a constraint
// error is found.
type ConstraintError struct {
	Type   string
	Name   string
	Detail string
}

// Error implements the error interface.
func (e ConstraintError) Error() string {
	return e.Detail
}

// StatusCode implements an status coder interface.
func (e ConstraintError) StatusCode() int {
	return http.StatusForbidden
}

// Engine implements a constraint validator for DNS names, IP addresses, Email
// addresses and URIs.
type Engine struct {
	hasNameConstraints      bool
	permittedDNSDomains     []string
	excludedDNSDomains      []string
	permittedIPRanges       []*net.IPNet
	excludedIPRanges        []*net.IPNet
	permittedEmailAddresses []string
	excludedEmailAddresses  []string
	permittedURIDomains     []string
	excludedURIDomains      []string
}

// New creates a constraint validation engine that contains the given chain of
// certificates.
func New(chain ...*x509.Certificate) *Engine {
	e := new(Engine)
	for _, crt := range chain {
		e.permittedDNSDomains = append(e.permittedDNSDomains, crt.PermittedDNSDomains...)
		e.excludedDNSDomains = append(e.excludedDNSDomains, crt.ExcludedDNSDomains...)
		e.permittedIPRanges = append(e.permittedIPRanges, crt.PermittedIPRanges...)
		e.excludedIPRanges = append(e.excludedIPRanges, crt.ExcludedIPRanges...)
		e.permittedEmailAddresses = append(e.permittedEmailAddresses, crt.PermittedEmailAddresses...)
		e.excludedEmailAddresses = append(e.excludedEmailAddresses, crt.ExcludedEmailAddresses...)
		e.permittedURIDomains = append(e.permittedURIDomains, crt.PermittedURIDomains...)
		e.excludedURIDomains = append(e.excludedURIDomains, crt.ExcludedURIDomains...)

		if !e.hasNameConstraints {
			for _, ext := range crt.Extensions {
				if ext.Id.Equal(oidExtensionNameConstraints) {
					e.hasNameConstraints = true
					break
				}
			}
		}
	}
	return e
}

// Validate checks the given names with the name constraints defined in the
// service.
func (e *Engine) Validate(dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL) error {
	if e == nil || !e.hasNameConstraints {
		return nil
	}

	for _, name := range dnsNames {
		if err := checkNameConstraints("DNS name", name, name, e.permittedDNSDomains, e.excludedDNSDomains,
			func(parsedName, constraint any) (bool, error) {
				return matchDomainConstraint(parsedName.(string), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	for _, ip := range ipAddresses {
		if err := checkNameConstraints("IP address", ip.String(), ip, e.permittedIPRanges, e.excludedIPRanges,
			func(parsedName, constraint any) (bool, error) {
				return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
			},
		); err != nil {
			return err
		}
	}

	for _, email := range emailAddresses {
		mailbox, ok := parseRFC2821Mailbox(email)
		if !ok {
			return fmt.Errorf("cannot parse rfc822Name %q", email)
		}
		if err := checkNameConstraints("Email address", email, mailbox, e.permittedEmailAddresses, e.excludedEmailAddresses,
			func(parsedName, constraint any) (bool, error) {
				return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	for _, uri := range uris {
		if err := checkNameConstraints("URI", uri.String(), uri, e.permittedURIDomains, e.excludedURIDomains,
			func(parsedName, constraint any) (bool, error) {
				return matchURIConstraint(parsedName.(*url.URL), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	return nil
}

// ValidateCertificate validates the DNS names, IP addresses, Email address and
// URIs present in the given certificate.
func (e *Engine) ValidateCertificate(cert *x509.Certificate) error {
	return e.Validate(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
}
