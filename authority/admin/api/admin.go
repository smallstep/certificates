package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
)

type adminAuthority interface {
	LoadProvisionerByName(string) (provisioner.Interface, error)
	GetProvisioners(cursor string, limit int) (provisioner.List, string, error)
	IsAdminAPIEnabled() bool
	LoadAdminByID(id string) (*linkedca.Admin, bool)
	GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error)
	StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error
	UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error)
	RemoveAdmin(ctx context.Context, id string) error
	AuthorizeAdminToken(r *http.Request, token string) (*linkedca.Admin, error)
	StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error
	LoadProvisionerByID(id string) (provisioner.Interface, error)
	UpdateProvisioner(ctx context.Context, nu *linkedca.Provisioner) error
	RemoveProvisioner(ctx context.Context, id string) error
	GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error)
	CreateAuthorityPolicy(ctx context.Context, admin *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error)
	UpdateAuthorityPolicy(ctx context.Context, admin *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error)
	RemoveAuthorityPolicy(ctx context.Context) error
}

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Subject     string              `json:"subject"`
	Provisioner string              `json:"provisioner"`
	Type        linkedca.Admin_Type `json:"type"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate() error {
	if car.Subject == "" {
		return admin.NewError(admin.ErrorBadRequestType, "subject cannot be empty")
	}
	if car.Provisioner == "" {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner cannot be empty")
	}
	switch car.Type {
	case linkedca.Admin_SUPER_ADMIN, linkedca.Admin_ADMIN:
	default:
		return admin.NewError(admin.ErrorBadRequestType, "invalid value for admin type")
	}
	return nil
}

// GetAdminsResponse for returning a list of admins.
type GetAdminsResponse struct {
	Admins     []*linkedca.Admin `json:"admins"`
	NextCursor string            `json:"nextCursor"`
}

// UpdateAdminRequest represents the body for a UpdateAdmin request.
type UpdateAdminRequest struct {
	Type linkedca.Admin_Type `json:"type"`
}

// Validate validates a new-admin request body.
func (uar *UpdateAdminRequest) Validate() error {
	switch uar.Type {
	case linkedca.Admin_SUPER_ADMIN, linkedca.Admin_ADMIN:
	default:
		return admin.NewError(admin.ErrorBadRequestType, "invalid value for admin type")
	}
	return nil
}

// DeleteResponse is the resource for successful DELETE responses.
type DeleteResponse struct {
	Status string `json:"status"`
}

// GetAdmin returns the requested admin, or an error.
func GetAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	adm, ok := mustAuthority(r.Context()).LoadAdminByID(id)
	if !ok {
		render.Error(w, admin.NewError(admin.ErrorNotFoundType,
			"admin %s not found", id))
		return
	}
	render.ProtoJSON(w, adm)
}

// GetAdmins returns a segment of admins associated with the authority.
func GetAdmins(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	admins, nextCursor, err := mustAuthority(r.Context()).GetAdmins(cursor, limit)
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error retrieving paginated admins"))
		return
	}
	render.JSON(w, &GetAdminsResponse{
		Admins:     admins,
		NextCursor: nextCursor,
	})
}

// CreateAdmin creates a new admin.
func CreateAdmin(w http.ResponseWriter, r *http.Request) {
	var body CreateAdminRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	auth := mustAuthority(r.Context())
	p, err := auth.LoadProvisionerByName(body.Provisioner)
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", body.Provisioner))
		return
	}
	adm := &linkedca.Admin{
		ProvisionerId: p.GetID(),
		Subject:       body.Subject,
		Type:          body.Type,
	}
	// Store to authority collection.
	if err := auth.StoreAdmin(r.Context(), adm, p); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error storing admin"))
		return
	}

	render.ProtoJSONStatus(w, adm, http.StatusCreated)
}

// DeleteAdmin deletes admin.
func DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := mustAuthority(r.Context()).RemoveAdmin(r.Context(), id); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error deleting admin %s", id))
		return
	}

	render.JSON(w, &DeleteResponse{Status: "ok"})
}

// UpdateAdmin updates an existing admin.
func UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	var body UpdateAdminRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	auth := mustAuthority(r.Context())
	adm, err := auth.UpdateAdmin(r.Context(), id, &linkedca.Admin{Type: body.Type})
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error updating admin %s", id))
		return
	}

	render.ProtoJSON(w, adm)
}
