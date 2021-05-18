package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/mgmt"
)

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Subject     string         `json:"subject"`
	Provisioner string         `json:"provisioner"`
	Type        mgmt.AdminType `json:"type"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate(c *admin.Collection) error {
	if _, ok := c.LoadBySubProv(car.Subject, car.Provisioner); ok {
		return mgmt.NewError(mgmt.ErrorBadRequestType,
			"admin with subject %s and provisioner name %s already exists", car.Subject, car.Provisioner)
	}
	return nil
}

// UpdateAdminRequest represents the body for a UpdateAdmin request.
type UpdateAdminRequest struct {
	Type mgmt.AdminType `json:"type"`
}

// Validate validates a new-admin request body.
func (uar *UpdateAdminRequest) Validate() error {
	return nil
}

// DeleteResponse is the resource for successful DELETE responses.
type DeleteResponse struct {
	Status string `json:"status"`
}

// GetAdmin returns the requested admin, or an error.
func (h *Handler) GetAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	prov, err := h.db.GetAdmin(ctx, id)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, prov)
}

// GetAdmins returns all admins associated with the authority.
func (h *Handler) GetAdmins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admins, err := h.db.GetAdmins(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, admins)
}

// CreateAdmin creates a new admin.
func (h *Handler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body CreateAdminRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, mgmt.WrapError(mgmt.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(h.auth.GetAdminCollection()); err != nil {
		api.WriteError(w, err)
		return
	}

	adm := &mgmt.Admin{
		ProvisionerName: body.Provisioner,
		Subject:         body.Subject,
		Type:            body.Type,
		Status:          mgmt.StatusActive,
	}
	if err := h.db.CreateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error creating admin"))
		return
	}
	api.JSON(w, adm)
	if err := h.auth.ReloadAuthConfig(); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// DeleteAdmin deletes admin.
func (h *Handler) DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.auth.GetAdminCollection().Count() == 1 {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorBadRequestType, "cannot remove last admin"))
		return
	}

	ctx := r.Context()
	adm, err := h.db.GetAdmin(ctx, id)
	if err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error retrieiving admin %s", id))
		return
	}
	adm.Status = mgmt.StatusDeleted
	if err := h.db.UpdateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error updating admin %s", id))
		return
	}
	api.JSON(w, &DeleteResponse{Status: "ok"})
	if err := h.auth.ReloadAuthConfig(); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// UpdateAdmin updates an existing admin.
func (h *Handler) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body UpdateAdminRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, mgmt.WrapError(mgmt.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	id := chi.URLParam(r, "id")

	adm, err := h.db.GetAdmin(ctx, id)
	if err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error retrieiving admin %s", id))
		return
	}

	// TODO validate

	adm.Type = body.Type

	if err := h.db.UpdateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error updating admin %s", id))
		return
	}
	api.JSON(w, adm)
	if err := h.auth.ReloadAuthConfig(); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}
