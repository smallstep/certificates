package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
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
func (h *Handler) GetAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	adm, ok := h.auth.LoadAdminByID(id)
	if !ok {
		api.WriteError(w, admin.NewError(admin.ErrorNotFoundType,
			"admin %s not found", id))
		return
	}
	api.ProtoJSON(w, adm)
}

// GetAdmins returns a segment of admins associated with the authority.
func (h *Handler) GetAdmins(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	admins, nextCursor, err := h.auth.GetAdmins(cursor, limit)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error retrieving paginated admins"))
		return
	}
	api.JSON(w, &GetAdminsResponse{
		Admins:     admins,
		NextCursor: nextCursor,
	})
}

// CreateAdmin creates a new admin.
func (h *Handler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	var body CreateAdminRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	p, err := h.auth.LoadProvisionerByName(body.Provisioner)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", body.Provisioner))
		return
	}
	adm := &linkedca.Admin{
		ProvisionerId: p.GetID(),
		Subject:       body.Subject,
		Type:          body.Type,
	}
	// Store to authority collection.
	if err := h.auth.StoreAdmin(r.Context(), adm, p); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error storing admin"))
		return
	}

	api.ProtoJSONStatus(w, adm, http.StatusCreated)
}

// DeleteAdmin deletes admin.
func (h *Handler) DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.auth.RemoveAdmin(r.Context(), id); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting admin %s", id))
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// UpdateAdmin updates an existing admin.
func (h *Handler) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	var body UpdateAdminRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	id := chi.URLParam(r, "id")

	adm, err := h.auth.UpdateAdmin(r.Context(), id, &linkedca.Admin{Type: body.Type})
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error updating admin %s", id))
		return
	}

	api.ProtoJSON(w, adm)
}
