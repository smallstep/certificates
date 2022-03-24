package authority

import (
	"context"
	"errors"
	"fmt"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	authPolicy "github.com/smallstep/certificates/authority/policy"
	policy "github.com/smallstep/certificates/policy"
)

func (a *Authority) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	p, err := a.adminDB.GetAuthorityPolicy(ctx)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (a *Authority) CreateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, p *linkedca.Policy) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.checkPolicy(ctx, adm, p); err != nil {
		return nil, err
	}

	if err := a.adminDB.CreateAuthorityPolicy(ctx, p); err != nil {
		return nil, err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return nil, admin.WrapErrorISE(err, "error reloading policy engines when creating authority policy")
	}

	return p, nil // TODO: return the newly stored policy
}

func (a *Authority) UpdateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, p *linkedca.Policy) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.checkPolicy(ctx, adm, p); err != nil {
		return nil, err
	}

	if err := a.adminDB.UpdateAuthorityPolicy(ctx, p); err != nil {
		return nil, err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return nil, admin.WrapErrorISE(err, "error reloading policy engines when updating authority policy")
	}

	return p, nil // TODO: return the updated stored policy
}

func (a *Authority) RemoveAuthorityPolicy(ctx context.Context) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.adminDB.DeleteAuthorityPolicy(ctx); err != nil {
		return err
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return admin.WrapErrorISE(err, "error reloading policy engines when deleting authority policy")
	}

	return nil
}

func (a *Authority) checkPolicy(ctx context.Context, adm *linkedca.Admin, p *linkedca.Policy) error {

	// convert the policy; return early if nil
	policyOptions := policyToCertificates(p)
	if policyOptions == nil {
		return nil
	}

	engine, err := authPolicy.NewX509PolicyEngine(policyOptions.GetX509Options())
	if err != nil {
		return admin.WrapErrorISE(err, "error creating temporary policy engine")
	}

	// TODO(hs): Provide option to force the policy, even when the admin subject would be locked out?

	sans := []string{adm.Subject}
	if err := isAllowed(engine, sans); err != nil {
		return err
	}

	// TODO(hs): perform the check for other admin subjects too?
	// What logic to use for that: do all admins need access? Only super admins? At least one?

	return nil
}

func isAllowed(engine authPolicy.X509Policy, sans []string) error {
	var (
		allowed bool
		err     error
	)
	if allowed, err = engine.AreSANsAllowed(sans); err != nil {
		var policyErr *policy.NamePolicyError
		if isPolicyErr := errors.As(err, &policyErr); isPolicyErr && policyErr.Reason == policy.NotAuthorizedForThisName {
			return fmt.Errorf("the provided policy would lock out %s from the CA. Please update your policy to include %s as an allowed name", sans, sans)
		}
		return err
	}

	if !allowed {
		return fmt.Errorf("the provided policy would lock out %s from the CA. Please update your policy to include %s as an allowed name", sans, sans)
	}

	return nil
}

func policyToCertificates(p *linkedca.Policy) *authPolicy.Options {

	// return early
	if p == nil {
		return nil
	}

	// prepare full policy struct
	opts := &authPolicy.Options{
		X509: &authPolicy.X509PolicyOptions{
			AllowedNames: &authPolicy.X509NameOptions{},
			DeniedNames:  &authPolicy.X509NameOptions{},
		},
		SSH: &authPolicy.SSHPolicyOptions{
			Host: &authPolicy.SSHHostCertificateOptions{
				AllowedNames: &authPolicy.SSHNameOptions{},
				DeniedNames:  &authPolicy.SSHNameOptions{},
			},
			User: &authPolicy.SSHUserCertificateOptions{
				AllowedNames: &authPolicy.SSHNameOptions{},
				DeniedNames:  &authPolicy.SSHNameOptions{},
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
