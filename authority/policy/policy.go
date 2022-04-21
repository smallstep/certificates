package policy

import (
	"fmt"

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
			policy.WithPermittedDNSDomains(allowed.DNSDomains...),
			policy.WithPermittedIPsOrCIDRs(allowed.IPRanges...),
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses...),
			policy.WithPermittedURIDomains(allowed.URIDomains...),
		)
	}

	denied := policyOptions.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
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

	if policyOptions.ShouldVerifySubjectCommonName() {
		options = append(options, policy.WithSubjectCommonNameVerification())
	}

	if policyOptions.IsWildcardLiteralAllowed() {
		options = append(options, policy.WithAllowLiteralWildcardNames())
	}

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
