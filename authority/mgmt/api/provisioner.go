package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/authority/status"
	"github.com/smallstep/certificates/errs"
)

// CreateProvisionerRequest represents the body for a CreateProvisioner request.
type CreateProvisionerRequest struct {
	Type             string       `json:"type"`
	Name             string       `json:"name"`
	Claims           *mgmt.Claims `json:"claims"`
	Details          []byte       `json:"details"`
	X509Template     string       `json:"x509Template"`
	X509TemplateData []byte       `json:"x509TemplateData"`
	SSHTemplate      string       `json:"sshTemplate"`
	SSHTemplateData  []byte       `json:"sshTemplateData"`
}

// Validate validates a new-provisioner request body.
func (cpr *CreateProvisionerRequest) Validate(c *provisioner.Collection) error {
	if _, ok := c.LoadByName(cpr.Name); ok {
		return mgmt.NewError(mgmt.ErrorBadRequestType, "provisioner with name %s already exists", cpr.Name)
	}
	return nil
}

// GetProvisionersResponse is the type for GET /admin/provisioners responses.
type GetProvisionersResponse struct {
	Provisioners provisioner.List `json:"provisioners"`
	NextCursor   string           `json:"nextCursor"`
}

// UpdateProvisionerRequest represents the body for a UpdateProvisioner request.
type UpdateProvisionerRequest struct {
	Type             string       `json:"type"`
	Name             string       `json:"name"`
	Claims           *mgmt.Claims `json:"claims"`
	Details          []byte       `json:"details"`
	X509Template     string       `json:"x509Template"`
	X509TemplateData []byte       `json:"x509TemplateData"`
	SSHTemplate      string       `json:"sshTemplate"`
	SSHTemplateData  []byte       `json:"sshTemplateData"`
}

// Validate validates a update-provisioner request body.
func (upr *UpdateProvisionerRequest) Validate(c *provisioner.Collection) error {
	if _, ok := c.LoadByName(upr.Name); ok {
		return mgmt.NewError(mgmt.ErrorBadRequestType, "provisioner with name %s already exists", upr.Name)
	}
	return nil
}

// GetProvisioner returns the requested provisioner, or an error.
func (h *Handler) GetProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	p, ok := h.auth.GetProvisionerCollection().LoadByName(name)
	if !ok {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorNotFoundType, "provisioner %s not found", name))
		return
	}

	prov, err := h.db.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, prov)
}

// GetProvisioners returns all provisioners associated with the authority.
func (h *Handler) GetProvisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		api.WriteError(w, mgmt.WrapError(mgmt.ErrorBadRequestType, err,
			"error parsing cursor / limt query params"))
		return
	}

	p, next, err := h.auth.GetProvisioners(cursor, limit)
	if err != nil {
		api.WriteError(w, errs.InternalServerErr(err))
		return
	}
	api.JSON(w, &GetProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// CreateProvisioner creates a new prov.
func (h *Handler) CreateProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var prov = new(mgmt.Provisioner)
	if err := api.ReadJSON(r.Body, prov); err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: validate

	// TODO: fix this
	prov.Claims = mgmt.NewDefaultClaims()

	if err := h.db.CreateProvisioner(ctx, prov); err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSONStatus(w, prov, http.StatusCreated)

	if err := h.auth.ReloadAuthConfig(); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// DeleteProvisioner deletes a provisioner.
func (h *Handler) DeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	p, ok := h.auth.GetProvisionerCollection().LoadByName(name)
	if !ok {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorNotFoundType, "provisioner %s not found", name))
		return
	}

	c := h.auth.GetAdminCollection()
	if c.SuperCount() == c.SuperCountByProvisioner(name) {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorBadRequestType,
			"cannot remove provisioner %s because no super admins will remain", name))
		return
	}

	ctx := r.Context()
	prov, err := h.db.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error loading provisioner %s from db", name))
		return
	}
	prov.Status = status.Deleted
	if err := h.db.UpdateProvisioner(ctx, prov); err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error updating provisioner %s", name))
		return
	}

	// Delete all admins associated with the provisioner.
	admins, ok := c.LoadByProvisioner(name)
	if ok {
		for _, adm := range admins {
			if err := h.db.UpdateAdmin(ctx, &mgmt.Admin{
				ID:            adm.ID,
				ProvisionerID: adm.ProvisionerID,
				Subject:       adm.Subject,
				Type:          adm.Type,
				Status:        status.Deleted,
			}); err != nil {
				api.WriteError(w, mgmt.WrapErrorISE(err, "error deleting admin %s, as part of provisioner %s deletion", adm.Subject, name))
				return
			}
		}
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})

	if err := h.auth.ReloadAuthConfig(); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// UpdateProvisioner updates an existing prov.
func (h *Handler) UpdateProvisioner(w http.ResponseWriter, r *http.Request) {
	/*
		ctx := r.Context()
		id := chi.URLParam(r, "id")

		var body UpdateProvisionerRequest
		if err := ReadJSON(r.Body, &body); err != nil {
			api.WriteError(w, err)
			return
		}
		if err := body.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		if prov, err := h.db.GetProvisioner(ctx, id); err != nil {
			api.WriteError(w, err)
			return
		}

		prov.Claims = body.Claims
		prov.Details = body.Provisioner
		prov.X509Template = body.X509Template
		prov.SSHTemplate = body.SSHTemplate
		prov.Status = body.Status

		if err := h.db.UpdateProvisioner(ctx, prov); err != nil {
			api.WriteError(w, err)
			return
		}
		api.JSON(w, prov)
	*/
}
