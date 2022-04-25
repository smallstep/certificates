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

type policyErrorType int

const (
	_ policyErrorType = iota
	AdminLockOut
	StoreFailure
	ReloadFailure
	ConfigurationFailure
	EvaluationFailure
	InternalFailure
)

type PolicyError struct {
	Typ policyErrorType
	Err error
}

func (p *PolicyError) Error() string {
	return p.Err.Error()
}

func (a *Authority) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	p, err := a.adminDB.GetAuthorityPolicy(ctx)
	if err != nil {
		return nil, &PolicyError{
			Typ: InternalFailure,
			Err: err,
		}
	}

	return p, nil
}

func (a *Authority) CreateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, p *linkedca.Policy) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.checkAuthorityPolicy(ctx, adm, p); err != nil {
		return nil, err
	}

	if err := a.adminDB.CreateAuthorityPolicy(ctx, p); err != nil {
		return nil, &PolicyError{
			Typ: StoreFailure,
			Err: err,
		}
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return nil, &PolicyError{
			Typ: ReloadFailure,
			Err: fmt.Errorf("error reloading policy engines when creating authority policy: %w", err),
		}
	}

	return p, nil
}

func (a *Authority) UpdateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, p *linkedca.Policy) (*linkedca.Policy, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.checkAuthorityPolicy(ctx, adm, p); err != nil {
		return nil, err
	}

	if err := a.adminDB.UpdateAuthorityPolicy(ctx, p); err != nil {
		return nil, &PolicyError{
			Typ: StoreFailure,
			Err: err,
		}
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return nil, &PolicyError{
			Typ: ReloadFailure,
			Err: fmt.Errorf("error reloading policy engines when updating authority policy: %w", err),
		}
	}

	return p, nil
}

func (a *Authority) RemoveAuthorityPolicy(ctx context.Context) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if err := a.adminDB.DeleteAuthorityPolicy(ctx); err != nil {
		return &PolicyError{
			Typ: StoreFailure,
			Err: err,
		}
	}

	if err := a.reloadPolicyEngines(ctx); err != nil {
		return &PolicyError{
			Typ: ReloadFailure,
			Err: fmt.Errorf("error reloading policy engines when deleting authority policy: %w", err),
		}
	}

	return nil
}

func (a *Authority) checkAuthorityPolicy(ctx context.Context, currentAdmin *linkedca.Admin, p *linkedca.Policy) error {

	// no policy and thus nothing to evaluate; return early
	if p == nil {
		return nil
	}

	// get all current admins from the database
	allAdmins, err := a.adminDB.GetAdmins(ctx)
	if err != nil {
		return &PolicyError{
			Typ: InternalFailure,
			Err: fmt.Errorf("error retrieving admins: %w", err),
		}
	}

	return a.checkPolicy(ctx, currentAdmin, allAdmins, p)
}

func (a *Authority) checkProvisionerPolicy(ctx context.Context, currentAdmin *linkedca.Admin, provName string, p *linkedca.Policy) error {

	// no policy and thus nothing to evaluate; return early
	if p == nil {
		return nil
	}

	// get all admins for the provisioner; ignoring case in which they're not found
	allProvisionerAdmins, _ := a.admins.LoadByProvisioner(provName)

	return a.checkPolicy(ctx, currentAdmin, allProvisionerAdmins, p)
}

// checkPolicy checks if a new or updated policy configuration results in the user
// locking themselves or other admins out of the CA.
func (a *Authority) checkPolicy(ctx context.Context, currentAdmin *linkedca.Admin, otherAdmins []*linkedca.Admin, p *linkedca.Policy) error {

	// convert the policy; return early if nil
	policyOptions := policyToCertificates(p)
	if policyOptions == nil {
		return nil
	}

	engine, err := authPolicy.NewX509PolicyEngine(policyOptions.GetX509Options())
	if err != nil {
		return &PolicyError{
			Typ: ConfigurationFailure,
			Err: err,
		}
	}

	// when an empty X.509 policy is provided, the resulting engine is nil
	// and there's no policy to evaluate.
	if engine == nil {
		return nil
	}

	// TODO(hs): Provide option to force the policy, even when the admin subject would be locked out?

	// check if the admin user that instructed the authority policy to be
	// created or updated, would still be allowed when the provided policy
	// would be applied.
	sans := []string{currentAdmin.GetSubject()}
	if err := isAllowed(engine, sans); err != nil {
		return err
	}

	// loop through admins to verify that none of them would be
	// locked out when the new policy were to be applied. Returns
	// an error with a message that includes the admin subject that
	// would be locked out.
	for _, adm := range otherAdmins {
		sans = []string{adm.GetSubject()}
		if err := isAllowed(engine, sans); err != nil {
			return err
		}
	}

	// TODO(hs): mask the error message for non-super admins?

	return nil
}

// reloadPolicyEngines reloads x509 and SSH policy engines using
// configuration stored in the DB or from the configuration file.
func (a *Authority) reloadPolicyEngines(ctx context.Context) error {
	var (
		err           error
		policyOptions *authPolicy.Options
	)

	if a.config.AuthorityConfig.EnableAdmin {

		// temporarily disable policy loading when LinkedCA is in use
		if _, ok := a.adminDB.(*linkedCaClient); ok {
			return nil
		}

		linkedPolicy, err := a.adminDB.GetAuthorityPolicy(ctx)
		if err != nil {
			var ae *admin.Error
			if isAdminError := errors.As(err, &ae); (isAdminError && ae.Type != admin.ErrorNotFoundType.String()) || !isAdminError {
				return fmt.Errorf("error getting policy to (re)load policy engines: %w", err)
			}
		}
		policyOptions = policyToCertificates(linkedPolicy)
	} else {
		policyOptions = a.config.AuthorityConfig.Policy
	}

	// if no new or updated policy option is set, clear policy engines that (may have)
	// been configured before and return early
	if policyOptions == nil {
		a.x509Policy = nil
		a.sshHostPolicy = nil
		a.sshUserPolicy = nil
		return nil
	}

	var (
		x509Policy    authPolicy.X509Policy
		sshHostPolicy authPolicy.HostPolicy
		sshUserPolicy authPolicy.UserPolicy
	)

	// initialize the x509 allow/deny policy engine
	if x509Policy, err = authPolicy.NewX509PolicyEngine(policyOptions.GetX509Options()); err != nil {
		return err
	}

	// initialize the SSH allow/deny policy engine for host certificates
	if sshHostPolicy, err = authPolicy.NewSSHHostPolicyEngine(policyOptions.GetSSHOptions()); err != nil {
		return err
	}

	// initialize the SSH allow/deny policy engine for user certificates
	if sshUserPolicy, err = authPolicy.NewSSHUserPolicyEngine(policyOptions.GetSSHOptions()); err != nil {
		return err
	}

	// set all policy engines; all or nothing
	a.x509Policy = x509Policy
	a.sshHostPolicy = sshHostPolicy
	a.sshUserPolicy = sshUserPolicy

	return nil
}

func isAllowed(engine authPolicy.X509Policy, sans []string) error {
	var (
		allowed bool
		err     error
	)
	if allowed, err = engine.AreSANsAllowed(sans); err != nil {
		var policyErr *policy.NamePolicyError
		isNamePolicyError := errors.As(err, &policyErr)
		if isNamePolicyError && policyErr.Reason == policy.NotAllowed {
			return &PolicyError{
				Typ: AdminLockOut,
				Err: fmt.Errorf("the provided policy would lock out %s from the CA. Please update your policy to include %s as an allowed name", sans, sans),
			}
		}
		return &PolicyError{
			Typ: EvaluationFailure,
			Err: err,
		}
	}

	if !allowed {
		return &PolicyError{
			Typ: AdminLockOut,
			Err: fmt.Errorf("the provided policy would lock out %s from the CA. Please update your policy to include %s as an allowed name", sans, sans),
		}
	}

	return nil
}

func policyToCertificates(p *linkedca.Policy) *authPolicy.Options {

	// return early
	if p == nil {
		return nil
	}

	// return early if x509 nor SSH is set
	if p.GetX509() == nil && p.GetSsh() == nil {
		return nil
	}

	opts := &authPolicy.Options{}

	// fill x509 policy configuration
	if x509 := p.GetX509(); x509 != nil {
		opts.X509 = &authPolicy.X509PolicyOptions{}
		if allow := x509.GetAllow(); allow != nil {
			opts.X509.AllowedNames = &authPolicy.X509NameOptions{}
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
		}
		if deny := x509.GetDeny(); deny != nil {
			opts.X509.DeniedNames = &authPolicy.X509NameOptions{}
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
		}

		opts.X509.AllowWildcardLiteral = x509.AllowWildcardLiteral
		opts.X509.DisableSubjectCommonNameVerification = x509.DisableSubjectCommonNameVerification
	}

	// fill ssh policy configuration
	if ssh := p.GetSsh(); ssh != nil {
		opts.SSH = &authPolicy.SSHPolicyOptions{}
		if host := ssh.GetHost(); host != nil {
			opts.SSH.Host = &authPolicy.SSHHostCertificateOptions{}
			if allow := host.GetAllow(); allow != nil {
				opts.SSH.Host.AllowedNames = &authPolicy.SSHNameOptions{}
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
				opts.SSH.Host.DeniedNames = &authPolicy.SSHNameOptions{}
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
			opts.SSH.User = &authPolicy.SSHUserCertificateOptions{}
			if allow := user.GetAllow(); allow != nil {
				opts.SSH.User.AllowedNames = &authPolicy.SSHNameOptions{}
				if allow.Emails != nil {
					opts.SSH.User.AllowedNames.EmailAddresses = allow.Emails
				}
				if allow.Principals != nil {
					opts.SSH.User.AllowedNames.Principals = allow.Principals
				}
			}
			if deny := user.GetDeny(); deny != nil {
				opts.SSH.User.DeniedNames = &authPolicy.SSHNameOptions{}
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
