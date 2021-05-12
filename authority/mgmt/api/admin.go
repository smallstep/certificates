package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/mgmt"
)

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Name          string `json:"name"`
	ProvisionerID string `json:"provisionerID"`
	IsSuperAdmin  bool   `json:"isSuperAdmin"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate() error {
	return nil
}

// UpdateAdminRequest represents the body for a UpdateAdmin request.
type UpdateAdminRequest struct {
	Name          string `json:"name"`
	ProvisionerID string `json:"provisionerID"`
	IsSuperAdmin  string `json:"isSuperAdmin"`
	Status        string `json:"status"`
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

	// TODO validate

	adm := &mgmt.Admin{
		ProvisionerID: body.ProvisionerID,
		Name:          body.Name,
		IsSuperAdmin:  body.IsSuperAdmin,
		Status:        mgmt.StatusActive,
	}
	if err := h.db.CreateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error creating admin"))
		return
	}
	api.JSON(w, adm)
}

// DeleteAdmin deletes admin.
func (h *Handler) DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

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

	if len(body.Name) > 0 {
		adm.Name = body.Name
	}
	if len(body.Status) > 0 {
		adm.Status = mgmt.StatusActive // FIXME
	}
	// Set IsSuperAdmin iff the string was set in the update request.
	if len(body.IsSuperAdmin) > 0 {
		adm.IsSuperAdmin = (body.IsSuperAdmin == "true")
	}
	if len(body.ProvisionerID) > 0 {
		adm.ProvisionerID = body.ProvisionerID
	}
	if err := h.db.UpdateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error updating admin %s", id))
		return
	}
	api.JSON(w, adm)
}
