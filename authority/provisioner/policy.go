package provisioner

import (
	"fmt"

	"github.com/smallstep/certificates/policy"
	"golang.org/x/crypto/ssh"
)

type sshPolicyEngineType string

const (
	userPolicyEngineType sshPolicyEngineType = "user"
	hostPolicyEngineType sshPolicyEngineType = "host"
)

var certTypeToPolicyEngineType = map[uint32]sshPolicyEngineType{
	uint32(ssh.UserCert): userPolicyEngineType,
	uint32(ssh.HostCert): hostPolicyEngineType,
}

type x509PolicyEngine interface {
	policy.X509NamePolicyEngine
}

type userPolicyEngine struct {
	policy.SSHNamePolicyEngine
}

type hostPolicyEngine struct {
	policy.SSHNamePolicyEngine
}

// newX509PolicyEngine creates a new x509 name policy engine
func newX509PolicyEngine(x509Opts *X509Options) (x509PolicyEngine, error) {

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
			policy.WithPermittedIPsOrCIDRs(allowed.IPRanges),
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			policy.WithPermittedURIDomains(allowed.URIDomains),
		)
	}

	denied := x509Opts.GetDeniedNameOptions()
	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedDNSDomains(denied.DNSDomains),
			policy.WithExcludedIPsOrCIDRs(denied.IPRanges),
			policy.WithExcludedEmailAddresses(denied.EmailAddresses),
			policy.WithExcludedURIDomains(denied.URIDomains),
		)
	}

	return policy.New(options...)
}

// newSSHUserPolicyEngine creates a new SSH user certificate policy engine
func newSSHUserPolicyEngine(sshOpts *SSHOptions) (*userPolicyEngine, error) {
	policyEngine, err := newSSHPolicyEngine(sshOpts, userPolicyEngineType)
	if err != nil {
		return nil, err
	}
	// ensure we're not wrapping a nil engine
	if policyEngine == nil {
		return nil, nil
	}
	return &userPolicyEngine{
		SSHNamePolicyEngine: policyEngine,
	}, nil
}

// newSSHHostPolicyEngine create a new SSH host certificate policy engine
func newSSHHostPolicyEngine(sshOpts *SSHOptions) (*hostPolicyEngine, error) {
	policyEngine, err := newSSHPolicyEngine(sshOpts, hostPolicyEngineType)
	if err != nil {
		return nil, err
	}
	// ensure we're not wrapping a nil engine
	if policyEngine == nil {
		return nil, nil
	}
	return &hostPolicyEngine{
		SSHNamePolicyEngine: policyEngine,
	}, nil
}

// newSSHPolicyEngine creates a new SSH name policy engine
func newSSHPolicyEngine(sshOpts *SSHOptions, typ sshPolicyEngineType) (policy.SSHNamePolicyEngine, error) {

	if sshOpts == nil {
		return nil, nil
	}

	var (
		allowed *SSHNameOptions
		denied  *SSHNameOptions
	)

	// TODO: embed the type in the policy engine itself for reference?
	switch typ {
	case userPolicyEngineType:
		if sshOpts.User != nil {
			allowed = sshOpts.User.GetAllowedNameOptions()
			denied = sshOpts.User.GetDeniedNameOptions()
		}
	case hostPolicyEngineType:
		if sshOpts.Host != nil {
			allowed = sshOpts.Host.AllowedNames
			denied = sshOpts.Host.DeniedNames
		}
	default:
		return nil, fmt.Errorf("unknown SSH policy engine type %s provided", typ)
	}

	options := []policy.NamePolicyOption{}

	if allowed != nil && allowed.HasNames() {
		options = append(options,
			policy.WithPermittedDNSDomains(allowed.DNSDomains),
			policy.WithPermittedIPsOrCIDRs(allowed.IPRanges),
			policy.WithPermittedEmailAddresses(allowed.EmailAddresses),
			policy.WithPermittedPrincipals(allowed.Principals),
		)
	}

	if denied != nil && denied.HasNames() {
		options = append(options,
			policy.WithExcludedDNSDomains(denied.DNSDomains),
			policy.WithExcludedIPsOrCIDRs(denied.IPRanges),
			policy.WithExcludedEmailAddresses(denied.EmailAddresses),
			policy.WithExcludedPrincipals(denied.Principals),
		)
	}

	// Return nil, because there's no policy to execute. This is
	// important, because the logic that determines user vs. host certs
	// are allowed depends on this fact. The two policy engines are
	// not aware of eachother, so this check is performed in the
	// SSH name validator, instead.
	if len(options) == 0 {
		return nil, nil
	}

	return policy.New(options...)
}
