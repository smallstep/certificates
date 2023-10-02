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
	AdminLockOut policyErrorType = iota + 1
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

func (a *Authority) checkProvisionerPolicy(ctx context.Context, provName string, p *linkedca.Policy) error {
	// no policy and thus nothing to evaluate; return early
	if p == nil {
		return nil
	}

	// get all admins for the provisioner; ignoring case in which they're not found
	allProvisionerAdmins, _ := a.admins.LoadByProvisioner(provName)

	// check the policy; pass in nil as the current admin, as all admins for the
	// provisioner will be checked by looping through allProvisionerAdmins. Also,
	// the current admin may be a super admin not belonging to the provisioner, so
	// can't be blocked, but is not required to be in the policy, either.
	return a.checkPolicy(ctx, nil, allProvisionerAdmins, p)
}

// checkPolicy checks if a new or updated policy configuration results in the user
// locking themselves or other admins out of the CA.
func (a *Authority) checkPolicy(_ context.Context, currentAdmin *linkedca.Admin, otherAdmins []*linkedca.Admin, p *linkedca.Policy) error {
	// convert the policy; return early if nil
	policyOptions := authPolicy.LinkedToCertificates(p)
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
	// would be applied. This case is skipped when current admin is nil, which
	// is the case when a provisioner policy is checked.
	if currentAdmin != nil {
		sans := []string{currentAdmin.GetSubject()}
		if err := isAllowed(engine, sans); err != nil {
			return err
		}
	}

	// loop through admins to verify that none of them would be
	// locked out when the new policy were to be applied. Returns
	// an error with a message that includes the admin subject that
	// would be locked out.
	for _, adm := range otherAdmins {
		sans := []string{adm.GetSubject()}
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
		policyOptions = authPolicy.LinkedToCertificates(linkedPolicy)
	} else {
		policyOptions = a.config.AuthorityConfig.Policy
	}

	engine, err := authPolicy.New(policyOptions)
	if err != nil {
		return err
	}

	// only update the policy engine when no error was returned
	a.policyEngine = engine

	return nil
}

func isAllowed(engine authPolicy.X509Policy, sans []string) error {
	if err := engine.AreSANsAllowed(sans); err != nil {
		var policyErr *policy.NamePolicyError
		isNamePolicyError := errors.As(err, &policyErr)
		if isNamePolicyError && policyErr.Reason == policy.NotAllowed {
			return &PolicyError{
				Typ: AdminLockOut,
				Err: fmt.Errorf("the provided policy would lock out %s from the CA. Please create an x509 policy to include %s as an allowed DNS name", sans, sans),
			}
		}
		return &PolicyError{
			Typ: EvaluationFailure,
			Err: err,
		}
	}

	return nil
}
