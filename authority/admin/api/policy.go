package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
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
}

// NewACMEAdminResponder returns a new ACMEAdminResponder
func NewPolicyAdminResponder(auth adminAuthority, adminDB admin.DB) *PolicyAdminResponder {
	return &PolicyAdminResponder{
		auth:    auth,
		adminDB: adminDB,
	}
}

// GetAuthorityPolicy handles the GET /admin/authority/policy request
func (par *PolicyAdminResponder) GetAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	policy, err := par.auth.GetAuthorityPolicy(r.Context())
	if ae, ok := err.(*admin.Error); ok {
		if !ae.IsType(admin.ErrorNotFoundType) {
			api.WriteError(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
			return
		}
	}

	if policy == nil {
		api.JSONNotFound(w)
		return
	}

	api.ProtoJSONStatus(w, policy, http.StatusOK)
}

// CreateAuthorityPolicy handles the POST /admin/authority/policy request
func (par *PolicyAdminResponder) CreateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	shouldWriteError := false
	if ae, ok := err.(*admin.Error); ok {
		shouldWriteError = !ae.IsType(admin.ErrorNotFoundType)
	}

	if shouldWriteError {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if policy != nil {
		adminErr := admin.NewError(admin.ErrorBadRequestType, "authority already has a policy")
		adminErr.Status = http.StatusConflict
		api.WriteError(w, adminErr)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := api.ReadProtoJSON(r.Body, newPolicy); err != nil {
		api.WriteError(w, err)
		return
	}

	adm, err := adminFromContext(ctx)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving admin from context"))
		return
	}

	if err := par.auth.StoreAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err, "error storing authority policy"))
		return
	}

	storedPolicy, err := par.auth.GetAuthorityPolicy(ctx)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving authority policy after updating"))
		return
	}

	api.JSONStatus(w, storedPolicy, http.StatusCreated)
}

// UpdateAuthorityPolicy handles the PUT /admin/authority/policy request
func (par *PolicyAdminResponder) UpdateAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	shouldWriteError := false
	if ae, ok := err.(*admin.Error); ok {
		shouldWriteError = !ae.IsType(admin.ErrorNotFoundType)
	}

	if shouldWriteError {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving authority policy"))
		return
	}

	if policy == nil {
		api.JSONNotFound(w)
		return
	}

	var newPolicy = new(linkedca.Policy)
	if err := api.ReadProtoJSON(r.Body, newPolicy); err != nil {
		api.WriteError(w, err)
		return
	}

	adm, err := adminFromContext(ctx)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving admin from context"))
		return
	}

	if err := par.auth.UpdateAuthorityPolicy(ctx, adm, newPolicy); err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err, "error updating authority policy"))
		return
	}

	newlyStoredPolicy, err := par.auth.GetAuthorityPolicy(ctx)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving authority policy after updating"))
		return
	}

	api.ProtoJSONStatus(w, newlyStoredPolicy, http.StatusOK)
}

// DeleteAuthorityPolicy handles the DELETE /admin/authority/policy request
func (par *PolicyAdminResponder) DeleteAuthorityPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	policy, err := par.auth.GetAuthorityPolicy(ctx)

	if ae, ok := err.(*admin.Error); ok {
		if !ae.IsType(admin.ErrorNotFoundType) {
			api.WriteError(w, admin.WrapErrorISE(ae, "error retrieving authority policy"))
			return
		}
	}

	if policy == nil {
		api.JSONNotFound(w)
		return
	}

	err = par.auth.RemoveAuthorityPolicy(ctx)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting authority policy"))
		return
	}

	api.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

// GetProvisionerPolicy handles the GET /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) GetProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	// TODO: move getting provisioner to middleware?
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = par.auth.LoadProvisionerByName(name); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
		return
	}

	prov, err := par.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	policy := prov.GetPolicy()
	if policy == nil {
		api.JSONNotFound(w)
		return
	}

	api.ProtoJSONStatus(w, policy, http.StatusOK)
}

// CreateProvisionerPolicy handles the POST /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) CreateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = par.auth.LoadProvisionerByName(name); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
		return
	}

	prov, err := par.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	policy := prov.GetPolicy()
	if policy != nil {
		adminErr := admin.NewError(admin.ErrorBadRequestType, "provisioner %s already has a policy", name)
		adminErr.Status = http.StatusConflict
		api.WriteError(w, adminErr)
	}

	var newPolicy = new(linkedca.Policy)
	if err := api.ReadProtoJSON(r.Body, newPolicy); err != nil {
		api.WriteError(w, err)
		return
	}

	prov.Policy = newPolicy

	err = par.auth.UpdateProvisioner(ctx, prov)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	api.ProtoJSONStatus(w, newPolicy, http.StatusCreated)
}

// UpdateProvisionerPolicy handles the PUT /admin/provisioners/{name}/policy request
func (par *PolicyAdminResponder) UpdateProvisionerPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = par.auth.LoadProvisionerByName(name); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
		return
	}

	prov, err := par.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	var policy = new(linkedca.Policy)
	if err := api.ReadProtoJSON(r.Body, policy); err != nil {
		api.WriteError(w, err)
		return
	}

	prov.Policy = policy
	err = par.auth.UpdateProvisioner(ctx, prov)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	api.ProtoJSONStatus(w, policy, http.StatusOK)
}

// DeleteProvisionerPolicy ...
func (par *PolicyAdminResponder) DeleteProvisionerPolicy(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	name := chi.URLParam(r, "name")
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = par.auth.LoadProvisionerByName(name); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
		return
	}

	prov, err := par.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	if prov.Policy == nil {
		api.JSONNotFound(w)
		return
	}

	// remove the policy
	prov.Policy = nil

	err = par.auth.UpdateProvisioner(ctx, prov)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// GetACMEAccountPolicy ...
func (par *PolicyAdminResponder) GetACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, "ok")
}

func (par *PolicyAdminResponder) CreateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, "ok")
}

func (par *PolicyAdminResponder) UpdateACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, "ok")
}

func (par *PolicyAdminResponder) DeleteACMEAccountPolicy(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, "ok")
}
