package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/linkedca"
)

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Subject     string              `json:"subject"`
	Provisioner string              `json:"provisioner"`
	Type        linkedca.Admin_Type `json:"type"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate() error {
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
	api.JSON(w, adm)
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

	api.JSON(w, adm)
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

	id := chi.URLParam(r, "id")

	adm, err := h.auth.UpdateAdmin(r.Context(), id, &linkedca.Admin{Type: body.Type})
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error updating admin %s", id))
		return
	}

	api.JSON(w, adm)
}
