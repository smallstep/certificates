package api

import (
	"context"
	"errors"
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/policy"
)

// PolicyAdminResponder is the interface responsible for writing ACME admin
// responses.
type PolicyAdminResponder interface {
	GetAuthorityPolicy(w http.ResponseWriter, r *http.Request)
	CreateAuthorityPolicy(w http.ResponseWriter, r *http.Request)
	UpdateAuthorityPolicy(w http.ResponseWriter, r *http.Request)
	DeleteAuthorityPolicy(w http.ResponseWriter, r *http.Request)
	GetProvisionerPolicy(w http.ResponseWriter, r *http.Request)
	CreateProvisionerPolicy(w http.ResponseWriter, r *http.Request)
	UpdateProvisionerPolicy(w http.ResponseWriter, r *http.Request)
	DeleteProvisionerPolicy(w http.ResponseWriter, r *http.Request)
	GetACMEAccountPolicy(w http.ResponseWriter, r *http.Request)
	CreateACMEAccountPolicy(w http.ResponseWriter, r *http.Request)
	UpdateACMEAccountPolicy(w http.ResponseWriter, r *http.Request)
	DeleteACMEAccountPolicy(w http.ResponseWriter, r *http.Request)
}

// policyAdminResponder implements PolicyAdminResponder.
type policyAdminResponder struct{}

// NewACMEAdminResponder returns a new PolicyAdminResponder.
func NewPolicyAdminResponder() PolicyAdminResponder {
	return &policyAdminResponder{}
}

// GetAuthorityPolicy handles the GET /admin/authority/policy request
func (par *policyAdminResponder) GetAuthorityPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	auth := mustAuthority(ctx)
	authorityPolicy, err := auth.GetAuthorityPolicy(r.Context())
	var ae *admin.Error
	if errors.As(err, &ae) && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
		return
	}

	if authorityPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, authorityPolicy, http.StatusOK)
}

// CreateAuthorityPolicy handles the POST /admin/authority/policy request
func (par *policyAdminResponder) CreateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	auth := mustAuthority(ctx)
	authorityPolicy, err := auth.GetAuthorityPolicy(ctx)

	var ae *admin.Error
	if errors.As(err, &ae) && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if authorityPolicy != nil {
		adminErr := admin.NewError(admin.ErrorConflictType, "authority already has a policy")
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating authority policy"))
		return
	}

	adm := linkedca.MustAdminFromContext(ctx)

	var createdPolicy *linkedca.Policy
	if createdPolicy, err = auth.CreateAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error storing authority policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error storing authority policy"))
		return
	}

	render.ProtoJSONStatus(w, createdPolicy, http.StatusCreated)
}

// UpdateAuthorityPolicy handles the PUT /admin/authority/policy request
func (par *policyAdminResponder) UpdateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	auth := mustAuthority(ctx)
	authorityPolicy, err := auth.GetAuthorityPolicy(ctx)

	var ae *admin.Error
	if errors.As(err, &ae) && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if authorityPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating authority policy"))
		return
	}

	adm := linkedca.MustAdminFromContext(ctx)

	var updatedPolicy *linkedca.Policy
	if updatedPolicy, err = auth.UpdateAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error updating authority policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error updating authority policy"))
		return
	}

	render.ProtoJSONStatus(w, updatedPolicy, http.StatusOK)
}

// DeleteAuthorityPolicy handles the DELETE /admin/authority/policy request
func (par *policyAdminResponder) DeleteAuthorityPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	auth := mustAuthority(ctx)
	authorityPolicy, err := auth.GetAuthorityPolicy(ctx)

	var ae *admin.Error
	if errors.As(err, &ae) && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
		return
	}

	if authorityPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	if err := auth.RemoveAuthorityPolicy(ctx); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting authority policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

// GetProvisionerPolicy handles the GET /admin/provisioners/{name}/policy request
func (par *policyAdminResponder) GetProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	provisionerPolicy := prov.GetPolicy()
	if provisionerPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, provisionerPolicy, http.StatusOK)
}

// CreateProvisionerPolicy handles the POST /admin/provisioners/{name}/policy request
func (par *policyAdminResponder) CreateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	provisionerPolicy := prov.GetPolicy()
	if provisionerPolicy != nil {
		adminErr := admin.NewError(admin.ErrorConflictType, "provisioner %s already has a policy", prov.Name)
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating provisioner policy"))
		return
	}

	prov.Policy = newPolicy
	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error creating provisioner policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error creating provisioner policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusCreated)
}

// UpdateProvisionerPolicy handles the PUT /admin/provisioners/{name}/policy request
func (par *policyAdminResponder) UpdateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	provisionerPolicy := prov.GetPolicy()
	if provisionerPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating provisioner policy"))
		return
	}

	prov.Policy = newPolicy
	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error updating provisioner policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error updating provisioner policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusOK)
}

// DeleteProvisionerPolicy handles the DELETE /admin/provisioners/{name}/policy request
func (par *policyAdminResponder) DeleteProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	if prov.Policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	// remove the policy
	prov.Policy = nil

	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting provisioner policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

func (par *policyAdminResponder) GetACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	eak := linkedca.MustExternalAccountKeyFromContext(ctx)
	eakPolicy := eak.GetPolicy()
	if eakPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, eakPolicy, http.StatusOK)
}

func (par *policyAdminResponder) CreateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	eak := linkedca.MustExternalAccountKeyFromContext(ctx)
	eakPolicy := eak.GetPolicy()
	if eakPolicy != nil {
		adminErr := admin.NewError(admin.ErrorConflictType, "ACME EAK %s already has a policy", eak.Id)
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating ACME EAK policy"))
		return
	}

	eak.Policy = newPolicy

	acmeEAK := linkedEAKToCertificates(eak)
	acmeDB := acme.MustDatabaseFromContext(ctx)
	if err := acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error creating ACME EAK policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusCreated)
}

func (par *policyAdminResponder) UpdateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	eak := linkedca.MustExternalAccountKeyFromContext(ctx)
	eakPolicy := eak.GetPolicy()
	if eakPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	newPolicy.Deduplicate()

	if err := validatePolicy(newPolicy); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error validating ACME EAK policy"))
		return
	}

	eak.Policy = newPolicy
	acmeEAK := linkedEAKToCertificates(eak)
	acmeDB := acme.MustDatabaseFromContext(ctx)
	if err := acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error updating ACME EAK policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusOK)
}

func (par *policyAdminResponder) DeleteACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := blockLinkedCA(ctx); err != nil {
		render.Error(w, err)
		return
	}

	prov := linkedca.MustProvisionerFromContext(ctx)
	eak := linkedca.MustExternalAccountKeyFromContext(ctx)
	eakPolicy := eak.GetPolicy()
	if eakPolicy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	// remove the policy
	eak.Policy = nil

	acmeEAK := linkedEAKToCertificates(eak)
	acmeDB := acme.MustDatabaseFromContext(ctx)
	if err := acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting ACME EAK policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

// blockLinkedCA blocks all API operations on linked deployments
func blockLinkedCA(ctx context.Context) error {
	// temporary blocking linked deployments
	adminDB := admin.MustFromContext(ctx)
	if a, ok := adminDB.(interface{ IsLinkedCA() bool }); ok && a.IsLinkedCA() {
		return admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
	}
	return nil
}

// isBadRequest checks if an error should result in a bad request error
// returned to the client.
func isBadRequest(err error) bool {
	var pe *authority.PolicyError
	isPolicyError := errors.As(err, &pe)
	return isPolicyError && (pe.Typ == authority.AdminLockOut || pe.Typ == authority.EvaluationFailure || pe.Typ == authority.ConfigurationFailure)
}

func validatePolicy(p *linkedca.Policy) error {
	// convert the policy; return early if nil
	options := policy.LinkedToCertificates(p)
	if options == nil {
		return nil
	}

	var err error

	// Initialize a temporary x509 allow/deny policy engine
	if _, err = policy.NewX509PolicyEngine(options.GetX509Options()); err != nil {
		return err
	}

	// Initialize a temporary SSH allow/deny policy engine for host certificates
	if _, err = policy.NewSSHHostPolicyEngine(options.GetSSHOptions()); err != nil {
		return err
	}

	// Initialize a temporary SSH allow/deny policy engine for user certificates
	if _, err = policy.NewSSHUserPolicyEngine(options.GetSSHOptions()); err != nil {
		return err
	}

	return nil
}
