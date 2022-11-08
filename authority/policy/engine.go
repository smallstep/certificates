package policy

import (
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Engine is a container for multiple policies.
type Engine struct {
	x509Policy    X509Policy
	sshUserPolicy UserPolicy
	sshHostPolicy HostPolicy
}

// New returns a new Engine using Options.
func New(options *Options) (*Engine, error) {
	// if no options provided, return early
	if options == nil {
		//nolint:nilnil // legacy
		return nil, nil
	}

	var (
		x509Policy    X509Policy
		sshHostPolicy HostPolicy
		sshUserPolicy UserPolicy
		err           error
	)

	// initialize the x509 allow/deny policy engine
	if x509Policy, err = NewX509PolicyEngine(options.GetX509Options()); err != nil {
		return nil, err
	}

	// initialize the SSH allow/deny policy engine for host certificates
	if sshHostPolicy, err = NewSSHHostPolicyEngine(options.GetSSHOptions()); err != nil {
		return nil, err
	}

	// initialize the SSH allow/deny policy engine for user certificates
	if sshUserPolicy, err = NewSSHUserPolicyEngine(options.GetSSHOptions()); err != nil {
		return nil, err
	}

	return &Engine{
		x509Policy:    x509Policy,
		sshHostPolicy: sshHostPolicy,
		sshUserPolicy: sshUserPolicy,
	}, nil
}

// IsX509CertificateAllowed evaluates an X.509 certificate against
// the X.509 policy (if available) and returns an error if one of the
// names in the certificate is not allowed.
func (e *Engine) IsX509CertificateAllowed(cert *x509.Certificate) error {
	// return early if there's no policy to evaluate
	if e == nil || e.x509Policy == nil {
		return nil
	}

	// return result of X.509 policy evaluation
	return e.x509Policy.IsX509CertificateAllowed(cert)
}

// AreSANsAllowed evaluates the slice of SANs against the X.509 policy
// (if available) and returns an error if one of the SANs is not allowed.
func (e *Engine) AreSANsAllowed(sans []string) error {
	// return early if there's no policy to evaluate
	if e == nil || e.x509Policy == nil {
		return nil
	}

	// return result of X.509 policy evaluation
	return e.x509Policy.AreSANsAllowed(sans)
}

// IsSSHCertificateAllowed evaluates an SSH certificate against the
// user or host policy (if configured) and returns an error if one of the
// principals in the certificate is not allowed.
func (e *Engine) IsSSHCertificateAllowed(cert *ssh.Certificate) error {
	// return early if there's no policy to evaluate
	if e == nil || (e.sshHostPolicy == nil && e.sshUserPolicy == nil) {
		return nil
	}

	switch cert.CertType {
	case ssh.HostCert:
		// when no host policy engine is configured, but a user policy engine is
		// configured, the host certificate is denied.
		if e.sshHostPolicy == nil && e.sshUserPolicy != nil {
			return errors.New("authority not allowed to sign ssh host certificates")
		}

		// return result of SSH host policy evaluation
		return e.sshHostPolicy.IsSSHCertificateAllowed(cert)
	case ssh.UserCert:
		// 	when no user policy engine is configured, but a host policy engine is
		// 	configured, the user certificate is denied.
		if e.sshUserPolicy == nil && e.sshHostPolicy != nil {
			return errors.New("authority not allowed to sign ssh user certificates")
		}

		// return result of SSH user policy evaluation
		return e.sshUserPolicy.IsSSHCertificateAllowed(cert)
	default:
		return fmt.Errorf("unexpected ssh certificate type %q", cert.CertType)
	}
}
