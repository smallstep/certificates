package provisioner

import "github.com/smallstep/certificates/authority/policy"

type policyEngine struct {
	x509Policy    policy.X509Policy
	sshHostPolicy policy.HostPolicy
	sshUserPolicy policy.UserPolicy
}

func newPolicyEngine(options *Options) (*policyEngine, error) {
	if options == nil {
		//nolint:nilnil // legacy
		return nil, nil
	}

	var (
		x509Policy    policy.X509Policy
		sshHostPolicy policy.HostPolicy
		sshUserPolicy policy.UserPolicy
		err           error
	)

	// Initialize the x509 allow/deny policy engine
	if x509Policy, err = policy.NewX509PolicyEngine(options.GetX509Options()); err != nil {
		return nil, err
	}

	// Initialize the SSH allow/deny policy engine for host certificates
	if sshHostPolicy, err = policy.NewSSHHostPolicyEngine(options.GetSSHOptions()); err != nil {
		return nil, err
	}

	// Initialize the SSH allow/deny policy engine for user certificates
	if sshUserPolicy, err = policy.NewSSHUserPolicyEngine(options.GetSSHOptions()); err != nil {
		return nil, err
	}

	return &policyEngine{
		x509Policy:    x509Policy,
		sshHostPolicy: sshHostPolicy,
		sshUserPolicy: sshUserPolicy,
	}, nil
}

func (p *policyEngine) getX509() policy.X509Policy {
	if p == nil {
		return nil
	}
	return p.x509Policy
}

func (p *policyEngine) getSSHHost() policy.HostPolicy {
	if p == nil {
		return nil
	}
	return p.sshHostPolicy
}

func (p *policyEngine) getSSHUser() policy.UserPolicy {
	if p == nil {
		return nil
	}
	return p.sshUserPolicy
}
