package authority

import (
	"context"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/policy"
	"go.step.sm/linkedca"
)

func (a *Authority) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	policy, err := a.adminDB.GetAuthorityPolicy(ctx)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func (a *Authority) StoreAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.adminDB.CreateAuthorityPolicy(ctx, policy); err != nil {
		return err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return admin.WrapErrorISE(err, "error reloading admin resources when creating authority policy")
	}

	return nil
}

func (a *Authority) UpdateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.adminDB.UpdateAuthorityPolicy(ctx, policy); err != nil {
		return err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return admin.WrapErrorISE(err, "error reloading admin resources when updating authority policy")
	}

	return nil
}

func (a *Authority) RemoveAuthorityPolicy(ctx context.Context) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.adminDB.DeleteAuthorityPolicy(ctx); err != nil {
		return err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return admin.WrapErrorISE(err, "error reloading admin resources when deleting authority policy")
	}

	return nil
}

func policyToCertificates(p *linkedca.Policy) *policy.Options {
	// return early
	if p == nil {
		return nil
	}
	// prepare full policy struct
	opts := &policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{},
			DeniedNames:  &policy.X509NameOptions{},
		},
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{},
				DeniedNames:  &policy.SSHNameOptions{},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{},
				DeniedNames:  &policy.SSHNameOptions{},
			},
		},
	}
	// fill x509 policy configuration
	if p.X509 != nil {
		if p.X509.Allow != nil {
			opts.X509.AllowedNames.DNSDomains = p.X509.Allow.Dns
			opts.X509.AllowedNames.IPRanges = p.X509.Allow.Ips
			opts.X509.AllowedNames.EmailAddresses = p.X509.Allow.Emails
			opts.X509.AllowedNames.URIDomains = p.X509.Allow.Uris
		}
		if p.X509.Deny != nil {
			opts.X509.DeniedNames.DNSDomains = p.X509.Deny.Dns
			opts.X509.DeniedNames.IPRanges = p.X509.Deny.Ips
			opts.X509.DeniedNames.EmailAddresses = p.X509.Deny.Emails
			opts.X509.DeniedNames.URIDomains = p.X509.Deny.Uris
		}
	}
	// fill ssh policy configuration
	if p.Ssh != nil {
		if p.Ssh.Host != nil {
			if p.Ssh.Host.Allow != nil {
				opts.SSH.Host.AllowedNames.DNSDomains = p.Ssh.Host.Allow.Dns
				opts.SSH.Host.AllowedNames.IPRanges = p.Ssh.Host.Allow.Ips
				opts.SSH.Host.AllowedNames.EmailAddresses = p.Ssh.Host.Allow.Principals
			}
			if p.Ssh.Host.Deny != nil {
				opts.SSH.Host.DeniedNames.DNSDomains = p.Ssh.Host.Deny.Dns
				opts.SSH.Host.DeniedNames.IPRanges = p.Ssh.Host.Deny.Ips
				opts.SSH.Host.DeniedNames.Principals = p.Ssh.Host.Deny.Principals
			}
		}
		if p.Ssh.User != nil {
			if p.Ssh.User.Allow != nil {
				opts.SSH.User.AllowedNames.EmailAddresses = p.Ssh.User.Allow.Emails
				opts.SSH.User.AllowedNames.Principals = p.Ssh.User.Allow.Principals
			}
			if p.Ssh.User.Deny != nil {
				opts.SSH.User.DeniedNames.EmailAddresses = p.Ssh.User.Deny.Emails
				opts.SSH.User.DeniedNames.Principals = p.Ssh.User.Deny.Principals
			}
		}
	}

	return opts
}
