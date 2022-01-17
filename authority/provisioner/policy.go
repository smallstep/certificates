package provisioner

import (
	"github.com/smallstep/certificates/policy"
)

// newX509PolicyEngine creates a new x509 name policy engine
func newX509PolicyEngine(x509Opts *X509Options) (policy.X509NamePolicyEngine, error) {

	if x509Opts == nil {
		return nil, nil
	}

	options := []policy.NamePolicyOption{
		policy.WithSubjectCommonNameVerification(), // enable x509 Subject Common Name validation by default
	}

	allowed := x509Opts.GetAllowedNameOptions()
	if allowed != nil && allowed.HasNames() {
		options = append(options,
			policy.WithPermittedDNSDomains(allowed.DNSDomains),
			policy.WithPermittedCIDRs(allowed.IPRanges), // TODO(hs): support IPs in addition to ranges
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			policy.WithPermittedURIDomains(allowed.URIDomains),
		)
	}

	denied := x509Opts.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedDNSDomains(denied.DNSDomains),
			policy.WithExcludedCIDRs(denied.IPRanges), // TODO(hs): support IPs in addition to ranges
			policy.WithExcludedEmailAddresses(denied.EmailAddresses),
			policy.WithExcludedURIDomains(denied.URIDomains),
		)
	}

	return policy.New(options...)
}

// newSSHPolicyEngine creates a new SSH name policy engine
func newSSHPolicyEngine(sshOpts *SSHOptions) (policy.SSHNamePolicyEngine, error) {

	if sshOpts == nil {
		return nil, nil
	}

	options := []policy.NamePolicyOption{}

	allowed := sshOpts.GetAllowedNameOptions()
	if allowed != nil && allowed.HasNames() {
		options = append(options,
			policy.WithPermittedDNSDomains(allowed.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			policy.WithPermittedPrincipals(allowed.Principals),
		)
	}

	denied := sshOpts.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedDNSDomains(denied.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			policy.WithExcludedEmailAddresses(denied.EmailAddresses),
			policy.WithExcludedPrincipals(denied.Principals),
		)
	}

	return policy.New(options...)
}
