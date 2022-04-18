package api

import (
	"errors"
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
)

type policyAdminResponderInterface interface {
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

// PolicyAdminResponder is responsible for writing ACME admin responses
type PolicyAdminResponder struct {
	auth    adminAuthority
	adminDB admin.DB
	acmeDB  acme.DB
}

// NewACMEAdminResponder returns a new ACMEAdminResponder
func NewPolicyAdminResponder(auth adminAuthority, adminDB admin.DB, acmeDB acme.DB) *PolicyAdminResponder {
	return &PolicyAdminResponder{
		auth:    auth,
		adminDB: adminDB,
		acmeDB:  acmeDB,
	}
}

// GetAuthorityPolicy handles the GET /admin/authority/policy request
func (par *PolicyAdminResponder) GetAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	policy, err := par.auth.GetAuthorityPolicy(r.Context())
	if ae, ok := err.(*admin.Error); ok && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
		return
	}

	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, policy, http.StatusOK)
}

// CreateAuthorityPolicy handles the POST /admin/authority/policy request
func (par *PolicyAdminResponder) CreateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	if ae, ok := err.(*admin.Error); ok && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if policy != nil {
		adminErr := admin.NewError(admin.ErrorBadRequestType, "authority already has a policy")
		adminErr.Status = http.StatusConflict
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	adm := linkedca.AdminFromContext(ctx)

	var createdPolicy *linkedca.Policy
	if createdPolicy, err = par.auth.CreateAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		var pe *authority.PolicyError
		isPolicyError := errors.As(err, &pe)

		if isPolicyError && pe.Typ == authority.AdminLockOut || pe.Typ == authority.EvaluationFailure || pe.Typ == authority.ConfigurationFailure {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, pe, "error storing authority policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error storing authority policy"))
		return
	}

	render.JSONStatus(w, createdPolicy, http.StatusCreated)
}

// UpdateAuthorityPolicy handles the PUT /admin/authority/policy request
func (par *PolicyAdminResponder) UpdateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	if ae, ok := err.(*admin.Error); ok && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	adm := linkedca.AdminFromContext(ctx)

	var updatedPolicy *linkedca.Policy
	if updatedPolicy, err = par.auth.UpdateAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		var pe *authority.PolicyError
		isPolicyError := errors.As(err, &pe)
		if isPolicyError && pe.Typ == authority.AdminLockOut || pe.Typ == authority.EvaluationFailure || pe.Typ == authority.ConfigurationFailure {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, pe, "error updating authority policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error updating authority policy"))
		return
	}

	render.ProtoJSONStatus(w, updatedPolicy, http.StatusOK)
}

// DeleteAuthorityPolicy handles the DELETE /admin/authority/policy request
func (par *PolicyAdminResponder) DeleteAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	if ae, ok := err.(*admin.Error); ok && !ae.IsType(admin.ErrorNotFoundType) {
		render.Error(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
		return
	}

	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist"))
		return
	}

	if err := par.auth.RemoveAuthorityPolicy(ctx); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting authority policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

// GetProvisionerPolicy handles the GET /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) GetProvisionerPolicy(w http.ResponseWriter, r *http.Request) {

	prov := linkedca.ProvisionerFromContext(r.Context())

	policy := prov.GetPolicy()
	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, policy, http.StatusOK)
}

// CreateProvisionerPolicy handles the POST /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) CreateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)

	policy := prov.GetPolicy()
	if policy != nil {
		adminErr := admin.NewError(admin.ErrorBadRequestType, "provisioner %s already has a policy", prov.Name)
		adminErr.Status = http.StatusConflict
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	prov.Policy = newPolicy

	if err := par.auth.UpdateProvisioner(ctx, prov); err != nil {
		var pe *authority.PolicyError
		isPolicyError := errors.As(err, &pe)
		if isPolicyError && pe.Typ == authority.AdminLockOut || pe.Typ == authority.EvaluationFailure || pe.Typ == authority.ConfigurationFailure {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, pe, "error creating provisioner policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error creating provisioner policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusCreated)
}

// UpdateProvisionerPolicy handles the PUT /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) UpdateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)

	if prov.Policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	prov.Policy = newPolicy
	if err := par.auth.UpdateProvisioner(ctx, prov); err != nil {
		var pe *authority.PolicyError
		isPolicyError := errors.As(err, &pe)
		if isPolicyError && pe.Typ == authority.AdminLockOut || pe.Typ == authority.EvaluationFailure || pe.Typ == authority.ConfigurationFailure {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, pe, "error updating provisioner policy"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error updating provisioner policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusOK)
}

// DeleteProvisionerPolicy handles the DELETE /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) DeleteProvisionerPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)

	if prov.Policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist"))
		return
	}

	// remove the policy
	prov.Policy = nil

	if err := par.auth.UpdateProvisioner(ctx, prov); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting provisioner policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

func (par *PolicyAdminResponder) GetACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eak := linkedca.ExternalAccountKeyFromContext(ctx)

	policy := eak.GetPolicy()
	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	render.ProtoJSONStatus(w, policy, http.StatusOK)
}

func (par *PolicyAdminResponder) CreateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)
	eak := linkedca.ExternalAccountKeyFromContext(ctx)

	policy := eak.GetPolicy()
	if policy != nil {
		adminErr := admin.NewError(admin.ErrorBadRequestType, "ACME EAK %s already has a policy", eak.Id)
		adminErr.Status = http.StatusConflict
		render.Error(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	eak.Policy = newPolicy

	acmeEAK := linkedEAKToCertificates(eak)
	if err := par.acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error creating ACME EAK policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusCreated)
}

func (par *PolicyAdminResponder) UpdateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)
	eak := linkedca.ExternalAccountKeyFromContext(ctx)

	policy := eak.GetPolicy()
	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := read.ProtoJSON(r.Body, newPolicy); err != nil {
		render.Error(w, err)
		return
	}

	eak.Policy = newPolicy
	acmeEAK := linkedEAKToCertificates(eak)
	if err := par.acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error updating ACME EAK policy"))
		return
	}

	render.ProtoJSONStatus(w, newPolicy, http.StatusOK)
}

func (par *PolicyAdminResponder) DeleteACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov := linkedca.ProvisionerFromContext(ctx)
	eak := linkedca.ExternalAccountKeyFromContext(ctx)

	policy := eak.GetPolicy()
	if policy == nil {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist"))
		return
	}

	// remove the policy
	eak.Policy = nil

	acmeEAK := linkedEAKToCertificates(eak)
	if err := par.acmeDB.UpdateExternalAccountKey(ctx, prov.GetId(), acmeEAK); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting ACME EAK policy"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}
