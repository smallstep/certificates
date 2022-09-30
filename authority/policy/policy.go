package policy

import (
	"fmt"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/policy"
)

// X509Policy is an alias for policy.X509NamePolicyEngine
type X509Policy policy.X509NamePolicyEngine

// UserPolicy is an alias for policy.SSHNamePolicyEngine
type UserPolicy policy.SSHNamePolicyEngine

// HostPolicy is an alias for policy.SSHNamePolicyEngine
type HostPolicy policy.SSHNamePolicyEngine

// NewX509PolicyEngine creates a new x509 name policy engine
func NewX509PolicyEngine(policyOptions X509PolicyOptionsInterface) (X509Policy, error) {
	// return early if no policy engine options to configure
	if policyOptions == nil {
		return nil, nil
	}

	options := []policy.NamePolicyOption{}

	allowed := policyOptions.GetAllowedNameOptions()
	if allowed != nil && allowed.HasNames() {
		options = append(options,
			policy.WithPermittedCommonNames(allowed.CommonNames...),
			policy.WithPermittedDNSDomains(allowed.DNSDomains...),
			policy.WithPermittedIPsOrCIDRs(allowed.IPRanges...),
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses...),
			policy.WithPermittedURIDomains(allowed.URIDomains...),
		)
	}

	denied := policyOptions.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedCommonNames(denied.CommonNames...),
			policy.WithExcludedDNSDomains(denied.DNSDomains...),
			policy.WithExcludedIPsOrCIDRs(denied.IPRanges...),
			policy.WithExcludedEmailAddresses(denied.EmailAddresses...),
			policy.WithExcludedURIDomains(denied.URIDomains...),
		)
	}

	// ensure no policy engine is returned when no name options were provided
	if len(options) == 0 {
		return nil, nil
	}

	// check if configuration specifies that wildcard names are allowed
	if policyOptions.AreWildcardNamesAllowed() {
		options = append(options, policy.WithAllowLiteralWildcardNames())
	}

	// enable subject common name verification by default
	options = append(options, policy.WithSubjectCommonNameVerification())

	return policy.New(options...)
}

type sshPolicyEngineType string

const (
	UserPolicyEngineType sshPolicyEngineType = "user"
	HostPolicyEngineType sshPolicyEngineType = "host"
)

// newSSHUserPolicyEngine creates a new SSH user certificate policy engine
func NewSSHUserPolicyEngine(policyOptions SSHPolicyOptionsInterface) (UserPolicy, error) {
	policyEngine, err := newSSHPolicyEngine(policyOptions, UserPolicyEngineType)
	if err != nil {
		return nil, err
	}
	return policyEngine, nil
}

// newSSHHostPolicyEngine create a new SSH host certificate policy engine
func NewSSHHostPolicyEngine(policyOptions SSHPolicyOptionsInterface) (HostPolicy, error) {
	policyEngine, err := newSSHPolicyEngine(policyOptions, HostPolicyEngineType)
	if err != nil {
		return nil, err
	}
	return policyEngine, nil
}

// newSSHPolicyEngine creates a new SSH name policy engine
func newSSHPolicyEngine(policyOptions SSHPolicyOptionsInterface, typ sshPolicyEngineType) (policy.SSHNamePolicyEngine, error) {
	// return early if no policy engine options to configure
	if policyOptions == nil {
		return nil, nil
	}

	var (
		allowed *SSHNameOptions
		denied  *SSHNameOptions
	)

	switch typ {
	case UserPolicyEngineType:
		allowed = policyOptions.GetAllowedUserNameOptions()
		denied = policyOptions.GetDeniedUserNameOptions()
	case HostPolicyEngineType:
		allowed = policyOptions.GetAllowedHostNameOptions()
		denied = policyOptions.GetDeniedHostNameOptions()
	default:
		return nil, fmt.Errorf("unknown SSH policy engine type %s provided", typ)
	}

	options := []policy.NamePolicyOption{}

	if allowed != nil && allowed.HasNames() {
		options = append(options,
			policy.WithPermittedDNSDomains(allowed.DNSDomains...),
			policy.WithPermittedIPsOrCIDRs(allowed.IPRanges...),
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses...),
			policy.WithPermittedPrincipals(allowed.Principals...),
		)
	}

	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedDNSDomains(denied.DNSDomains...),
			policy.WithExcludedIPsOrCIDRs(denied.IPRanges...),
			policy.WithExcludedEmailAddresses(denied.EmailAddresses...),
			policy.WithExcludedPrincipals(denied.Principals...),
		)
	}

	// ensure no policy engine is returned when no name options were provided
	if len(options) == 0 {
		return nil, nil
	}

	return policy.New(options...)
}

func LinkedToCertificates(p *linkedca.Policy) *Options {
	// return early
	if p == nil {
		return nil
	}

	// return early if x509 nor SSH is set
	if p.GetX509() == nil && p.GetSsh() == nil {
		return nil
	}

	opts := &Options{}

	// fill x509 policy configuration
	if x509 := p.GetX509(); x509 != nil {
		opts.X509 = &X509PolicyOptions{}
		if allow := x509.GetAllow(); allow != nil {
			opts.X509.AllowedNames = &X509NameOptions{}
			if allow.Dns != nil {
				opts.X509.AllowedNames.DNSDomains = allow.Dns
			}
			if allow.Ips != nil {
				opts.X509.AllowedNames.IPRanges = allow.Ips
			}
			if allow.Emails != nil {
				opts.X509.AllowedNames.EmailAddresses = allow.Emails
			}
			if allow.Uris != nil {
				opts.X509.AllowedNames.URIDomains = allow.Uris
			}
			if allow.CommonNames != nil {
				opts.X509.AllowedNames.CommonNames = allow.CommonNames
			}
		}
		if deny := x509.GetDeny(); deny != nil {
			opts.X509.DeniedNames = &X509NameOptions{}
			if deny.Dns != nil {
				opts.X509.DeniedNames.DNSDomains = deny.Dns
			}
			if deny.Ips != nil {
				opts.X509.DeniedNames.IPRanges = deny.Ips
			}
			if deny.Emails != nil {
				opts.X509.DeniedNames.EmailAddresses = deny.Emails
			}
			if deny.Uris != nil {
				opts.X509.DeniedNames.URIDomains = deny.Uris
			}
			if deny.CommonNames != nil {
				opts.X509.DeniedNames.CommonNames = deny.CommonNames
			}
		}

		opts.X509.AllowWildcardNames = x509.GetAllowWildcardNames()
	}

	// fill ssh policy configuration
	if ssh := p.GetSsh(); ssh != nil {
		opts.SSH = &SSHPolicyOptions{}
		if host := ssh.GetHost(); host != nil {
			opts.SSH.Host = &SSHHostCertificateOptions{}
			if allow := host.GetAllow(); allow != nil {
				opts.SSH.Host.AllowedNames = &SSHNameOptions{}
				if allow.Dns != nil {
					opts.SSH.Host.AllowedNames.DNSDomains = allow.Dns
				}
				if allow.Ips != nil {
					opts.SSH.Host.AllowedNames.IPRanges = allow.Ips
				}
				if allow.Principals != nil {
					opts.SSH.Host.AllowedNames.Principals = allow.Principals
				}
			}
			if deny := host.GetDeny(); deny != nil {
				opts.SSH.Host.DeniedNames = &SSHNameOptions{}
				if deny.Dns != nil {
					opts.SSH.Host.DeniedNames.DNSDomains = deny.Dns
				}
				if deny.Ips != nil {
					opts.SSH.Host.DeniedNames.IPRanges = deny.Ips
				}
				if deny.Principals != nil {
					opts.SSH.Host.DeniedNames.Principals = deny.Principals
				}
			}
		}
		if user := ssh.GetUser(); user != nil {
			opts.SSH.User = &SSHUserCertificateOptions{}
			if allow := user.GetAllow(); allow != nil {
				opts.SSH.User.AllowedNames = &SSHNameOptions{}
				if allow.Emails != nil {
					opts.SSH.User.AllowedNames.EmailAddresses = allow.Emails
				}
				if allow.Principals != nil {
					opts.SSH.User.AllowedNames.Principals = allow.Principals
				}
			}
			if deny := user.GetDeny(); deny != nil {
				opts.SSH.User.DeniedNames = &SSHNameOptions{}
				if deny.Emails != nil {
					opts.SSH.User.DeniedNames.EmailAddresses = deny.Emails
				}
				if deny.Principals != nil {
					opts.SSH.User.DeniedNames.Principals = deny.Principals
				}
			}
		}
	}

	return opts
}
