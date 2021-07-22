package api

import (
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
)

// Handler is the ACME API request handler.
type Handler struct {
	db     admin.DB
	auth   *authority.Authority
	acmeDB acme.DB
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(auth *authority.Authority, adminDB admin.DB, acmeDB acme.DB) api.RouterHandler {
	return &Handler{
		db:     adminDB,
		auth:   auth,
		acmeDB: acmeDB,
	}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	authnz := func(next nextHTTP) nextHTTP {
		return h.extractAuthorizeTokenAdmin(h.requireAPIEnabled(next))
	}

	// Provisioners
	r.MethodFunc("GET", "/provisioners/{name}", authnz(h.GetProvisioner))
	r.MethodFunc("GET", "/provisioners", authnz(h.GetProvisioners))
	r.MethodFunc("POST", "/provisioners", authnz(h.CreateProvisioner))
	r.MethodFunc("PUT", "/provisioners/{name}", authnz(h.UpdateProvisioner))
	r.MethodFunc("DELETE", "/provisioners/{name}", authnz(h.DeleteProvisioner))

	// Admins
	r.MethodFunc("GET", "/admins/{id}", authnz(h.GetAdmin))
	r.MethodFunc("GET", "/admins", authnz(h.GetAdmins))
	r.MethodFunc("POST", "/admins", authnz(h.CreateAdmin))
	r.MethodFunc("PATCH", "/admins/{id}", authnz(h.UpdateAdmin))
	r.MethodFunc("DELETE", "/admins/{id}", authnz(h.DeleteAdmin))

	// External Account Binding Keys
	r.MethodFunc("POST", "/eak", authnz(h.CreateExternalAccountKey))
}
