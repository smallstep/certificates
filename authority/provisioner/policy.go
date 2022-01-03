package provisioner

import (
	sshpolicy "github.com/smallstep/certificates/policy/ssh"
	x509policy "github.com/smallstep/certificates/policy/x509"
)

// newX509PolicyEngine creates a new x509 name policy engine
func newX509PolicyEngine(x509Opts *X509Options) (*x509policy.NamePolicyEngine, error) {

	if x509Opts == nil {
		return nil, nil
	}

	options := []x509policy.NamePolicyOption{
		x509policy.WithEnableSubjectCommonNameVerification(), // enable x509 Subject Common Name validation by default
	}

	allowed := x509Opts.GetAllowedNameOptions()
	if allowed != nil && allowed.HasNames() {
		options = append(options,
			x509policy.WithPermittedDNSDomains(allowed.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			x509policy.WithPermittedCIDRs(allowed.IPRanges),        // TODO(hs): support IPs in addition to ranges
			x509policy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			x509policy.WithPermittedURIDomains(allowed.URIDomains),
		)
	}

	denied := x509Opts.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			x509policy.WithExcludedDNSDomains(denied.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			x509policy.WithExcludedCIDRs(denied.IPRanges),        // TODO(hs): support IPs in addition to ranges
			x509policy.WithExcludedEmailAddresses(denied.EmailAddresses),
			x509policy.WithExcludedURIDomains(denied.URIDomains),
		)
	}

	return x509policy.New(options...)
}

// newSSHPolicyEngine creates a new SSH name policy engine
func newSSHPolicyEngine(sshOpts *SSHOptions) (*sshpolicy.NamePolicyEngine, error) {

	if sshOpts == nil {
		return nil, nil
	}

	options := []sshpolicy.NamePolicyOption{}

	allowed := sshOpts.GetAllowedNameOptions()
	if allowed != nil && allowed.HasNames() {
		options = append(options,
			sshpolicy.WithPermittedDNSDomains(allowed.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			sshpolicy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			sshpolicy.WithPermittedPrincipals(allowed.Principals),
		)
	}

	denied := sshOpts.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			sshpolicy.WithExcludedDNSDomains(denied.DNSDomains), // TODO(hs): be a bit more lenient w.r.t. the format of domains? I.e. allow "*.localhost" instead of the ".localhost", which is what Name Constraints do.
			sshpolicy.WithExcludedEmailAddresses(denied.EmailAddresses),
			sshpolicy.WithExcludedPrincipals(denied.Principals),
		)
	}

	return sshpolicy.New(options...)
}
