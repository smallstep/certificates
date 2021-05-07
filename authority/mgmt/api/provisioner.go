package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/mgmt"
)

// CreateProvisionerRequest represents the body for a CreateProvisioner request.
type CreateProvisionerRequest struct {
	Type         string       `json:"type"`
	Name         string       `json:"name"`
	Claims       *mgmt.Claims `json:"claims"`
	Details      interface{}  `json:"details"`
	X509Template string       `json:"x509Template"`
	SSHTemplate  string       `json:"sshTemplate"`
}

// Validate validates a new-provisioner request body.
func (car *CreateProvisionerRequest) Validate() error {
	return nil
}

// UpdateProvisionerRequest represents the body for a UpdateProvisioner request.
type UpdateProvisionerRequest struct {
	Claims       *mgmt.Claims `json:"claims"`
	Details      interface{}  `json:"details"`
	X509Template string       `json:"x509Template"`
	SSHTemplate  string       `json:"sshTemplate"`
}

// Validate validates a new-provisioner request body.
func (uar *UpdateProvisionerRequest) Validate() error {
	return nil
}

// GetProvisioner returns the requested provisioner, or an error.
func (h *Handler) GetProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	prov, err := h.db.GetProvisioner(ctx, id)
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
	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
	}

	prov := &mgmt.Provisioner{
		Type:         body.Type,
		Name:         body.Name,
		Claims:       body.Claims,
		Details:      body.Details,
		X509Template: body.X509Template,
		SSHTemplate:  body.SSHTemplate,
	}
	if err := h.db.CreateProvisioner(ctx, prov); err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSONStatus(w, prov, http.StatusCreated)
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
