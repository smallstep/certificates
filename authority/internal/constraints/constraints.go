package constraints

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
)

var oidExtensionNameConstraints = []int{2, 5, 29, 30}

type ConstraintError struct {
	Type   string
	Name   string
	Detail string
}

func (e ConstraintError) Error() string {
	return e.Detail
}

type service struct {
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

func New(chain ...*x509.Certificate) *service {
	s := new(service)
	for _, crt := range chain {
		s.permittedDNSDomains = append(s.permittedDNSDomains, crt.PermittedDNSDomains...)
		s.excludedDNSDomains = append(s.excludedDNSDomains, crt.ExcludedDNSDomains...)
		s.permittedIPRanges = append(s.permittedIPRanges, crt.PermittedIPRanges...)
		s.excludedIPRanges = append(s.excludedIPRanges, crt.ExcludedIPRanges...)
		s.permittedEmailAddresses = append(s.permittedEmailAddresses, crt.PermittedEmailAddresses...)
		s.excludedEmailAddresses = append(s.excludedEmailAddresses, crt.ExcludedEmailAddresses...)
		s.permittedURIDomains = append(s.permittedURIDomains, crt.PermittedURIDomains...)
		s.excludedURIDomains = append(s.excludedURIDomains, crt.ExcludedURIDomains...)

		if !s.hasNameConstraints {
			for _, ext := range crt.Extensions {
				if ext.Id.Equal(oidExtensionNameConstraints) {
					s.hasNameConstraints = true
					break
				}
			}
		}
	}
	return s
}

// Validates
func (s *service) Validate(dnsNames []string, ipAddresses []*net.IP, emailAddresses []string, uris []*url.URL) error {
	if !s.hasNameConstraints {
		return nil
	}

	for _, name := range dnsNames {
		if err := checkNameConstraints("DNS name", name, name, s.permittedDNSDomains, s.excludedDNSDomains,
			func(parsedName, constraint any) (bool, error) {
				return matchDomainConstraint(parsedName.(string), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	for _, ip := range ipAddresses {
		if err := checkNameConstraints("IP address", ip.String(), ip, s.permittedIPRanges, s.excludedIPRanges,
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
		if err := checkNameConstraints("Email address", email, mailbox, s.permittedEmailAddresses, s.excludedEmailAddresses,
			func(parsedName, constraint any) (bool, error) {
				return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	for _, uri := range uris {
		if err := checkNameConstraints("URI", uri.String(), uri, s.permittedURIDomains, s.excludedURIDomains,
			func(parsedName, constraint any) (bool, error) {
				return matchURIConstraint(parsedName.(*url.URL), constraint.(string))
			},
		); err != nil {
			return err
		}
	}

	return nil
}
