package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/authority/provisioner"
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

	prov, err := h.db.GetProvisionerByName(ctx, name)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, prov)
}

// GetProvisioners returns all provisioners associated with the authority.
func (h *Handler) GetProvisioners(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	provs, err := h.db.GetProvisioners(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, provs)
}

// CreateProvisioner creates a new prov.
func (h *Handler) CreateProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body CreateProvisionerRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := body.Validate(h.auth.GetProvisionerCollection()); err != nil {
		api.WriteError(w, err)
		return
	}

	details, err := mgmt.UnmarshalProvisionerDetails(body.Details)
	if err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error unmarshaling provisioner details"))
		return
	}

	claims := mgmt.NewDefaultClaims()

	prov := &mgmt.Provisioner{
		Type:             body.Type,
		Name:             body.Name,
		Claims:           claims,
		Details:          details,
		X509Template:     body.X509Template,
		X509TemplateData: body.X509TemplateData,
		SSHTemplate:      body.SSHTemplate,
		SSHTemplateData:  body.SSHTemplateData,
	}
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

	c := h.auth.GetAdminCollection()
	if c.Count() == c.CountByProvisioner(name) {
		api.WriteError(w, mgmt.NewError(mgmt.ErrorBadRequestType,
			"cannot remove provisioner %s because no admins will remain", name))
		return
	}

	ctx := r.Context()
	prov, err := h.db.GetProvisionerByName(ctx, name)
	if err != nil {
		api.WriteError(w, mgmt.WrapErrorISE(err, "error retrieiving provisioner %s", name))
		return
	}
	fmt.Printf("prov = %+v\n", prov)
	prov.Status = mgmt.StatusDeleted
	if err := h.db.UpdateProvisioner(ctx, name, prov); err != nil {
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
				Type:          mgmt.AdminType(adm.Type),
				Status:        mgmt.StatusDeleted,
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
