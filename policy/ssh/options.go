package sshpolicy

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type NamePolicyOption func(g *NamePolicyEngine) error

func WithPermittedDNSDomains(domains []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse permitted domain constraint %q", domain)
			}
		}
		g.permittedDNSDomains = domains
		return nil
	}
}

func WithExcludedDNSDomains(domains []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		for _, domain := range domains {
			if err := validateDNSDomainConstraint(domain); err != nil {
				return errors.Errorf("cannot parse excluded domain constraint %q", domain)
			}
		}
		g.excludedDNSDomains = domains
		return nil
	}
}

func WithPermittedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		g.permittedEmailAddresses = emailAddresses
		return nil
	}
}

func WithExcludedEmailAddresses(emailAddresses []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		for _, email := range emailAddresses {
			if err := validateEmailConstraint(email); err != nil {
				return err
			}
		}
		g.excludedEmailAddresses = emailAddresses
		return nil
	}
}

func WithPermittedPrincipals(principals []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		// for _, principal := range principals {
		// 	// TODO: validation?
		// }
		g.permittedPrincipals = principals
		return nil
	}
}

func WithExcludedPrincipals(principals []string) NamePolicyOption {
	return func(g *NamePolicyEngine) error {
		// for _, principal := range principals {
		// 	// TODO: validation?
		// }
		g.excludedPrincipals = principals
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
