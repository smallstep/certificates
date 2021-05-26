package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/linkedca"
)

// CreateAdminRequest represents the body for a CreateAdmin request.
type CreateAdminRequest struct {
	Subject     string              `json:"subject"`
	Provisioner string              `json:"provisioner"`
	Type        linkedca.Admin_Type `json:"type"`
}

// Validate validates a new-admin request body.
func (car *CreateAdminRequest) Validate(c *admin.Collection) error {
	if _, ok := c.LoadBySubProv(car.Subject, car.Provisioner); ok {
		return mgmt.NewError(mgmt.ErrorBadRequestType,
			"admin with subject: '%s' and provisioner: '%s' already exists", car.Subject, car.Provisioner)
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
	return nil
}

// DeleteResponse is the resource for successful DELETE responses.
type DeleteResponse struct {
	Status string `json:"status"`
}

// GetAdmin returns the requested admin, or an error.
func (h *Handler) GetAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	adm, ok := h.auth.GetAdminCollection().LoadByID(id)
	if !ok {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorNotFoundType,
			"admin %s not found", id))
		return
	}
	api.JSON(w, adm)
}

// GetAdmins returns all admins associated with the authority.
func (h *Handler) GetAdmins(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		api.WriteError(w, mgmt.WrapError(mgmt.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	admins, nextCursor := h.auth.GetAdminCollection().Find(cursor, limit)
	api.JSON(w, &GetAdminsResponse{
		Admins:     admins,
		NextCursor: nextCursor,
	})
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

	p, ok := h.auth.GetProvisionerCollection().LoadByName(body.Provisioner)
	if !ok {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorNotFoundType, "provisioner %s not found", body.Provisioner))
		return
	}

	adm := &linkedca.Admin{
		ProvisionerId: p.GetID(),
		Subject:       body.Subject,
		Type:          body.Type,
	}
	if err := h.db.CreateAdmin(ctx, adm); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error creating admin"))
		return
	}
	api.JSON(w, adm)
	if err := h.auth.ReloadAuthConfig(ctx); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// DeleteAdmin deletes admin.
func (h *Handler) DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.auth.GetAdminCollection().SuperCount() == 1 {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorBadRequestType, "cannot remove the last super admin"))
		return
	}

	ctx := r.Context()
	if err := h.db.DeleteAdmin(ctx, id); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error deleting admin %s", id))
		return
	}
	api.JSON(w, &DeleteResponse{Status: "ok"})

	if err := h.auth.ReloadAuthConfig(ctx); err != nil {
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

	adm, ok := h.auth.GetAdminCollection().LoadByID(id)
	if !ok {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorNotFoundType, "admin %s not found", id))
		return
	}
	if adm.Type == body.Type {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorBadRequestType, "admin %s already has type %s", id, adm.Type))
		return
	}

	adm.Type = body.Type

	if err := h.db.UpdateAdmin(ctx, (*linkedca.Admin)(adm)); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error updating admin %s", id))
		return
	}
	api.JSON(w, adm)
	if err := h.auth.ReloadAuthConfig(ctx); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}
