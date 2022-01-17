package x509policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
)

type NamePolicyOption func(e *NamePolicyEngine) error

// TODO: wrap (more) errors; and prove a set of known (exported) errors

func WithSubjectCommonNameVerification() NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.verifySubjectCommonName = true
		return nil
	}
}

func WithAllowLiteralWildcardNames() NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		e.allowLiteralWildcardNames = true
		return nil
	}
}

func WithPermittedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomains := make([]string, len(domains))
		for i, domain := range domains {
			normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
			if err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
			normalizedDomains[i] = normalizedDomain
		}
		e.permittedDNSDomains = normalizedDomains
		return nil
	}
}

func AddPermittedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomains := make([]string, len(domains))
		for i, domain := range domains {
			normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
			if err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
			normalizedDomains[i] = normalizedDomain
		}
		e.permittedDNSDomains = append(e.permittedDNSDomains, normalizedDomains...)
		return nil
	}
}

func WithExcludedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomains := make([]string, len(domains))
		for i, domain := range domains {
			normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
			if err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
			normalizedDomains[i] = normalizedDomain
		}
		e.excludedDNSDomains = normalizedDomains
		return nil
	}
}

func AddExcludedDNSDomains(domains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomains := make([]string, len(domains))
		for i, domain := range domains {
			normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
			if err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
			normalizedDomains[i] = normalizedDomain
		}
		e.excludedDNSDomains = append(e.excludedDNSDomains, normalizedDomains...)
		return nil
	}
}

func WithPermittedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
		if err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.permittedDNSDomains = []string{normalizedDomain}
		return nil
	}
}

func AddPermittedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
		if err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.permittedDNSDomains = append(e.permittedDNSDomains, normalizedDomain)
		return nil
	}
}

func WithExcludedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
		if err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.excludedDNSDomains = []string{normalizedDomain}
		return nil
	}
}

func AddExcludedDNSDomain(domain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedDomain, err := normalizeAndValidateDNSDomainConstraint(domain)
		if err != nil {
			return errors.Errorf("cannot parse permitted domain constraint %q", domain)
		}
		e.excludedDNSDomains = append(e.excludedDNSDomains, normalizedDomain)
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
		networks := make([]*net.IPNet, len(cidrs))
		for i, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
			}
			networks[i] = nw
		}
		e.permittedIPRanges = networks
		return nil
	}
}

func AddPermittedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := make([]*net.IPNet, len(cidrs))
		for i, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse permitted CIDR constraint %q", cidr)
			}
			networks[i] = nw
		}
		e.permittedIPRanges = append(e.permittedIPRanges, networks...)
		return nil
	}
}

func WithExcludedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := make([]*net.IPNet, len(cidrs))
		for i, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
			}
			networks[i] = nw
		}
		e.excludedIPRanges = networks
		return nil
	}
}

func AddExcludedCIDRs(cidrs []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		networks := make([]*net.IPNet, len(cidrs))
		for i, cidr := range cidrs {
			_, nw, err := net.ParseCIDR(cidr)
			if err != nil {
				return errors.Errorf("cannot parse excluded CIDR constraint %q", cidr)
			}
			networks[i] = nw
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
		normalizedEmailAddresses := make([]string, len(emailAddresses))
		for i, email := range emailAddresses {
			normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(email)
			if err != nil {
				return err
			}
			normalizedEmailAddresses[i] = normalizedEmailAddress
		}
		e.permittedEmailAddresses = normalizedEmailAddresses
		return nil
	}
}

func AddPermittedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddresses := make([]string, len(emailAddresses))
		for i, email := range emailAddresses {
			normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(email)
			if err != nil {
				return err
			}
			normalizedEmailAddresses[i] = normalizedEmailAddress
		}
		e.permittedEmailAddresses = append(e.permittedEmailAddresses, normalizedEmailAddresses...)
		return nil
	}
}

func WithExcludedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddresses := make([]string, len(emailAddresses))
		for i, email := range emailAddresses {
			normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(email)
			if err != nil {
				return err
			}
			normalizedEmailAddresses[i] = normalizedEmailAddress
		}
		e.excludedEmailAddresses = normalizedEmailAddresses
		return nil
	}
}

func AddExcludedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddresses := make([]string, len(emailAddresses))
		for i, email := range emailAddresses {
			normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(email)
			if err != nil {
				return err
			}
			normalizedEmailAddresses[i] = normalizedEmailAddress
		}
		e.excludedEmailAddresses = append(e.excludedEmailAddresses, normalizedEmailAddresses...)
		return nil
	}
}

func WithPermittedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(emailAddress)
		if err != nil {
			return err
		}
		e.permittedEmailAddresses = []string{normalizedEmailAddress}
		return nil
	}
}

func AddPermittedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(emailAddress)
		if err != nil {
			return err
		}
		e.permittedEmailAddresses = append(e.permittedEmailAddresses, normalizedEmailAddress)
		return nil
	}
}

func WithExcludedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(emailAddress)
		if err != nil {
			return err
		}
		e.excludedEmailAddresses = []string{normalizedEmailAddress}
		return nil
	}
}

func AddExcludedEmailAddress(emailAddress string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedEmailAddress, err := normalizeAndValidateEmailConstraint(emailAddress)
		if err != nil {
			return err
		}
		e.excludedEmailAddresses = append(e.excludedEmailAddresses, normalizedEmailAddress)
		return nil
	}
}

func WithPermittedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomains := make([]string, len(uriDomains))
		for i, domain := range uriDomains {
			normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(domain)
			if err != nil {
				return err
			}
			normalizedURIDomains[i] = normalizedURIDomain
		}
		e.permittedURIDomains = normalizedURIDomains
		return nil
	}
}

func AddPermittedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomains := make([]string, len(uriDomains))
		for i, domain := range uriDomains {
			normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(domain)
			if err != nil {
				return err
			}
			normalizedURIDomains[i] = normalizedURIDomain
		}
		e.permittedURIDomains = append(e.permittedURIDomains, normalizedURIDomains...)
		return nil
	}
}

func WithPermittedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(uriDomain)
		if err != nil {
			return err
		}
		e.permittedURIDomains = []string{normalizedURIDomain}
		return nil
	}
}

func AddPermittedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(uriDomain)
		if err != nil {
			return err
		}
		e.permittedURIDomains = append(e.permittedURIDomains, normalizedURIDomain)
		return nil
	}
}

func WithExcludedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomains := make([]string, len(uriDomains))
		for i, domain := range uriDomains {
			normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(domain)
			if err != nil {
				return err
			}
			normalizedURIDomains[i] = normalizedURIDomain
		}
		e.excludedURIDomains = normalizedURIDomains
		return nil
	}
}

func AddExcludedURIDomains(uriDomains []string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomains := make([]string, len(uriDomains))
		for i, domain := range uriDomains {
			normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(domain)
			if err != nil {
				return err
			}
			normalizedURIDomains[i] = normalizedURIDomain
		}
		e.excludedURIDomains = append(e.excludedURIDomains, normalizedURIDomains...)
		return nil
	}
}

func WithExcludedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(uriDomain)
		if err != nil {
			return err
		}
		e.excludedURIDomains = []string{normalizedURIDomain}
		return nil
	}
}

func AddExcludedURIDomain(uriDomain string) NamePolicyOption {
	return func(e *NamePolicyEngine) error {
		normalizedURIDomain, err := normalizeAndValidateURIDomainConstraint(uriDomain)
		if err != nil {
			return err
		}
		e.excludedURIDomains = append(e.excludedURIDomains, normalizedURIDomain)
		return nil
	}
}

func normalizeAndValidateDNSDomainConstraint(constraint string) (string, error) {
	normalizedConstraint := strings.TrimSpace(constraint)
	if strings.Contains(normalizedConstraint, "..") {
		return "", errors.Errorf("domain constraint %q cannot have empty labels", constraint)
	}
	if strings.HasPrefix(normalizedConstraint, "*.") {
		normalizedConstraint = normalizedConstraint[1:] // cut off wildcard character; keep the period
	}
	if strings.Contains(normalizedConstraint, "*") {
		return "", errors.Errorf("domain constraint %q can only have wildcard as starting character", constraint)
	}
	if _, ok := domainToReverseLabels(normalizedConstraint); !ok {
		return "", errors.Errorf("cannot parse permitted domain constraint %q", constraint)
	}
	return normalizedConstraint, nil
}

func normalizeAndValidateEmailConstraint(constraint string) (string, error) {
	normalizedConstraint := strings.TrimSpace(constraint)
	if strings.Contains(normalizedConstraint, "*") {
		return "", fmt.Errorf("email constraint %q cannot contain asterisk", constraint)
	}
	if strings.Count(normalizedConstraint, "@") > 1 {
		return "", fmt.Errorf("email constraint %q contains too many @ characters", constraint)
	}
	if normalizedConstraint[0] == '@' {
		normalizedConstraint = normalizedConstraint[1:] // remove the leading @ as wildcard for emails
	}
	if normalizedConstraint[0] == '.' {
		return "", fmt.Errorf("email constraint %q cannot start with period", constraint)
	}
	if strings.Contains(normalizedConstraint, "@") {
		if _, ok := parseRFC2821Mailbox(normalizedConstraint); !ok {
			return "", fmt.Errorf("cannot parse email constraint %q", constraint)
		}
	}
	if _, ok := domainToReverseLabels(normalizedConstraint); !ok {
		return "", fmt.Errorf("cannot parse email domain constraint %q", constraint)
	}
	return normalizedConstraint, nil
}

func normalizeAndValidateURIDomainConstraint(constraint string) (string, error) {
	normalizedConstraint := strings.TrimSpace(constraint)
	if strings.Contains(normalizedConstraint, "..") {
		return "", errors.Errorf("URI domain constraint %q cannot have empty labels", constraint)
	}
	if strings.HasPrefix(normalizedConstraint, "*.") {
		normalizedConstraint = normalizedConstraint[1:] // cut off wildcard character; keep the period
	}
	if strings.Contains(normalizedConstraint, "*") {
		return "", errors.Errorf("URI domain constraint %q can only have wildcard as starting character", constraint)
	}
	// TODO(hs): block constraints that look like IPs too? Because hosts can't be matched to those.
	_, ok := domainToReverseLabels(normalizedConstraint)
	if !ok {
		return "", fmt.Errorf("cannot parse URI domain constraint %q", constraint)
	}
	return normalizedConstraint, nil
}
