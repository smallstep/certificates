package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/mgmt"
)

// CreateAuthConfigRequest represents the body for a CreateAuthConfig request.
type CreateAuthConfigRequest struct {
	ASN1DN   *config.ASN1DN `json:"asn1dn,omitempty"`
	Claims   *mgmt.Claims   `json:"claims,omitempty"`
	Backdate string         `json:"backdate,omitempty"`
}

// Validate validates a CreateAuthConfig request body.
func (car *CreateAuthConfigRequest) Validate() error {
	return nil
}

// UpdateAuthConfigRequest represents the body for a UpdateAuthConfig request.
type UpdateAuthConfigRequest struct {
	ASN1DN   *config.ASN1DN `json:"asn1dn"`
	Claims   *mgmt.Claims   `json:"claims"`
	Backdate string         `json:"backdate,omitempty"`
}

// Validate validates a new-admin request body.
func (uar *UpdateAuthConfigRequest) Validate() error {
	return nil
}

// GetAuthConfig returns the requested admin, or an error.
func (h *Handler) GetAuthConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	ac, err := h.db.GetAuthConfig(ctx, id)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, ac)
}

// CreateAuthConfig creates a new admin.
func (h *Handler) CreateAuthConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body CreateAuthConfigRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
	}

	ac := &mgmt.AuthConfig{
		Status:   mgmt.StatusActive,
		Backdate: "1m",
	}
	if body.ASN1DN != nil {
		ac.ASN1DN = body.ASN1DN
	}
	if body.Claims != nil {
		ac.Claims = body.Claims
	}
	if body.Backdate != "" {
		ac.Backdate = body.Backdate
	}
	if err := h.db.CreateAuthConfig(ctx, ac); err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSONStatus(w, ac, http.StatusCreated)
}

// UpdateAuthConfig updates an existing AuthConfig.
func (h *Handler) UpdateAuthConfig(w http.ResponseWriter, r *http.Request) {
	/*
		ctx := r.Context()
		id := chi.URLParam(r, "id")

		var body UpdateAuthConfigRequest
		if err := api.ReadJSON(r.Body, &body); err != nil {
			api.WriteError(w, err)
			return
		}
		if err := body.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		ac, err := h.db.GetAuthConfig(ctx, id)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		ac.Status = body.Status
		if body.ASN1DN != nil {
			ac.ASN1DN = body.ASN1DN
		}
		if body.Claims != nil {
			ac.Claims = body.Claims
		}
		if body.Backdate != "" {
			ac.Backdate = body.Backdate
		}

		if err := h.db.UpdateAuthConfig(ctx, ac); err != nil {
			api.WriteError(w, err)
			return
		}
		api.JSON(w, ac)
	*/
}
