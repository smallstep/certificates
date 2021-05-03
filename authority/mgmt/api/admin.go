package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
)

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Name         string `json:"name"`
	Provisioner  string `json:"provisioner"`
	IsSuperAdmin bool   `json:"isSuperAdmin"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate() error {
	return nil
}

// UpdateAdminRequest represents the body for a UpdateAdmin request.
type UpdateAdminRequest struct {
	Name         string `json:"name"`
	Provisioner  string `json:"provisioner"`
	IsSuperAdmin bool   `json:"isSuperAdmin"`
}

// Validate validates a new-admin request body.
func (uar *UpdateAdminRequest) Validate() error {
	return nil
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
	if err := ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
	}

	adm := &config.Admin{
		Name:         body.Name,
		Provisioner:  body.Provisioner,
		IsSuperAdmin: body.IsSuperAdmin,
	}
	if err := h.db.CreateAdmin(ctx, adm); err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSONStatus(w, adm, http.StatusCreated)
}

// UpdateAdmin updates an existing admin.
func (h *Handler) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var body UpdateAdminRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}
	if adm, err := h.db.GetAdmin(ctx, id); err != nil {
		api.WriteError(w, err)
		return
	}

	adm.Name = body.Name
	adm.Provisioner = body.Provisioner
	adm.IsSuperAdmin = body.IsSuperAdmin

	if err := h.db.UpdateAdmin(ctx, adm); err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, adm)
}
