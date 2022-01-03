package x509policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
)

type NamePolicyOption func(e *NamePolicyEngine) error

// TODO: wrap (more) errors; and prove a set of known (exported) errors

func WithEnableSubjectCommonNameVerification() NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.verifySubjectCommonName = true
		return nil
	}
}

func WithPermittedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
		}
		e.permittedDNSDomains = domains
		return nil
	}
}

func AddPermittedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
		}
		e.permittedDNSDomains = append(e.permittedDNSDomains, domains...)
		return nil
	}
}

func WithExcludedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse excluded domain constraint %q", domain)
			}
		}
		e.excludedDNSDomains = domains
		return nil
	}
}

func AddExcludedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse excluded domain constraint %q", domain)
			}
		}
		e.excludedDNSDomains = append(e.excludedDNSDomains, domains...)
		return nil
	}
}

func WithPermittedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateDNSDomainConstraint(domain); err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.permittedDNSDomains = []string{domain}
		return nil
	}
}

func AddPermittedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateDNSDomainConstraint(domain); err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.permittedDNSDomains = append(e.permittedDNSDomains, domain)
		return nil
	}
}

func WithExcludedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateDNSDomainConstraint(domain); err != nil {
			return errors.Errorf("cannot parse excluded domain constraint %q", domain)
		}
		e.excludedDNSDomains = []string{domain}
		return nil
	}
}

func AddExcludedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateDNSDomainConstraint(domain); err != nil {
			return errors.Errorf("cannot parse excluded domain constraint %q", domain)
		}
		e.excludedDNSDomains = append(e.excludedDNSDomains, domain)
		return nil
	}
}

func WithPermittedIPRanges(ipRanges []*net.IPNet) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.permittedIPRanges = ipRanges
		return nil
	}
}

func AddPermittedIPRanges(ipRanges []*net.IPNet) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.permittedIPRanges = append(e.permittedIPRanges, ipRanges...)
		return nil
	}
}

func WithPermittedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := []*net.IPNet{}
		for _, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
			}
			networks = append(networks, nw)
		}
		e.permittedIPRanges = networks
		return nil
	}
}

func AddPermittedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := []*net.IPNet{}
		for _, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
			}
			networks = append(networks, nw)
		}
		e.permittedIPRanges = append(e.permittedIPRanges, networks...)
		return nil
	}
}

func WithExcludedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := []*net.IPNet{}
		for _, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
			}
			networks = append(networks, nw)
		}
		e.excludedIPRanges = networks
		return nil
	}
}

func AddExcludedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := []*net.IPNet{}
		for _, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
			}
			networks = append(networks, nw)
		}
		e.excludedIPRanges = append(e.excludedIPRanges, networks...)
		return nil
	}
}

func WithPermittedCIDR(cidr string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		_, nw, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
		}
		e.permittedIPRanges = []*net.IPNet{nw}
		return nil
	}
}

func AddPermittedCIDR(cidr string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		_, nw, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
		}
		e.permittedIPRanges = append(e.permittedIPRanges, nw)
		return nil
	}
}

func WithPermittedIP(ip net.IP) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		var mask net.IPMask
		if !isIPv4(ip) {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(32, 32)
		}
		nw := &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
		e.permittedIPRanges = []*net.IPNet{nw}
		return nil
	}
}

func AddPermittedIP(ip net.IP) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		var mask net.IPMask
		if !isIPv4(ip) {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(32, 32)
		}
		nw := &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
		e.permittedIPRanges = append(e.permittedIPRanges, nw)
		return nil
	}
}

func WithExcludedIPRanges(ipRanges []*net.IPNet) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.excludedIPRanges = ipRanges
		return nil
	}
}

func AddExcludedIPRanges(ipRanges []*net.IPNet) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.excludedIPRanges = append(e.excludedIPRanges, ipRanges...)
		return nil
	}
}

func WithExcludedCIDR(cidr string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		_, nw, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
		}
		e.excludedIPRanges = []*net.IPNet{nw}
		return nil
	}
}

func AddExcludedCIDR(cidr string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		_, nw, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
		}
		e.excludedIPRanges = append(e.excludedIPRanges, nw)
		return nil
	}
}

func WithExcludedIP(ip net.IP) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		var mask net.IPMask
		if !isIPv4(ip) {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(32, 32)
		}
		nw := &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
		e.excludedIPRanges = []*net.IPNet{nw}
		return nil
	}
}

func AddExcludedIP(ip net.IP) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		var mask net.IPMask
		if !isIPv4(ip) {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(32, 32)
		}
		nw := &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
		e.excludedIPRanges = append(e.excludedIPRanges, nw)
		return nil
	}
}

func WithPermittedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		e.permittedEmailAddresses = emailAddresses
		return nil
	}
}

func AddPermittedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		e.permittedEmailAddresses = append(e.permittedEmailAddresses, emailAddresses...)
		return nil
	}
}

func WithExcludedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		e.excludedEmailAddresses = emailAddresses
		return nil
	}
}

func AddExcludedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		e.excludedEmailAddresses = append(e.excludedEmailAddresses, emailAddresses...)
		return nil
	}
}

func WithPermittedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateEmailConstraint(emailAddress); err != nil {
			return err
		}
		e.permittedEmailAddresses = []string{emailAddress}
		return nil
	}
}

func AddPermittedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateEmailConstraint(emailAddress); err != nil {
			return err
		}
		e.permittedEmailAddresses = append(e.permittedEmailAddresses, emailAddress)
		return nil
	}
}

func WithExcludedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateEmailConstraint(emailAddress); err != nil {
			return err
		}
		e.excludedEmailAddresses = []string{emailAddress}
		return nil
	}
}

func AddExcludedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateEmailConstraint(emailAddress); err != nil {
			return err
		}
		e.excludedEmailAddresses = append(e.excludedEmailAddresses, emailAddress)
		return nil
	}
}

func WithPermittedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range uriDomains {
			if err := validateURIDomainConstraint(domain); err != nil {
				return err
			}
		}
		e.permittedURIDomains = uriDomains
		return nil
	}
}

func AddPermittedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range uriDomains {
			if err := validateURIDomainConstraint(domain); err != nil {
				return err
			}
		}
		e.permittedURIDomains = append(e.permittedURIDomains, uriDomains...)
		return nil
	}
}

func WithPermittedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateURIDomainConstraint(uriDomain); err != nil {
			return err
		}
		e.permittedURIDomains = []string{uriDomain}
		return nil
	}
}

func AddPermittedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateURIDomainConstraint(uriDomain); err != nil {
			return err
		}
		e.permittedURIDomains = append(e.permittedURIDomains, uriDomain)
		return nil
	}
}

func WithExcludedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range uriDomains {
			if err := validateURIDomainConstraint(domain); err != nil {
				return err
			}
		}
		e.excludedURIDomains = uriDomains
		return nil
	}
}

func AddExcludedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		for _, domain := range uriDomains {
			if err := validateURIDomainConstraint(domain); err != nil {
				return err
			}
		}
		e.excludedURIDomains = append(e.excludedURIDomains, uriDomains...)
		return nil
	}
}

func WithExcludedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateURIDomainConstraint(uriDomain); err != nil {
			return err
		}
		e.excludedURIDomains = []string{uriDomain}
		return nil
	}
}

func AddExcludedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		if err := validateURIDomainConstraint(uriDomain); err != nil {
			return err
		}
		e.excludedURIDomains = append(e.excludedURIDomains, uriDomain)
		return nil
	}
}

func validateDNSDomainConstraint(domain string) error {
	if _, ok := domainToReverseLabels(domain); !ok {
		return errors.Errorf("cannot parse permitted domain constraint %q", domain)
	}
	return nil
}

func validateEmailConstraint(constraint string) error {
	if strings.Contains(constraint, "@") {
		_, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return fmt.Errorf("cannot parse email constraint %q", constraint)
		}
	}
	_, ok := domainToReverseLabels(constraint)
	if !ok {
		return fmt.Errorf("cannot parse email domain constraint %q", constraint)
	}
	return nil
}

func validateURIDomainConstraint(constraint string) error {
	_, ok := domainToReverseLabels(constraint)
	if !ok {
		return fmt.Errorf("cannot parse URI domain constraint %q", constraint)
	}
	return nil
}
