package api

import (
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
)

// Handler is the Admin API request handler.
type Handler struct {
	adminDB       admin.DB
	auth          adminAuthority
	acmeDB        acme.DB
	acmeResponder acmeAdminResponderInterface
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(auth adminAuthority, adminDB admin.DB, acmeDB acme.DB, acmeResponder acmeAdminResponderInterface) api.RouterHandler {
	return &Handler{
		auth:          auth,
		adminDB:       adminDB,
		acmeDB:        acmeDB,
		acmeResponder: acmeResponder,
	}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	authnz := func(next nextHTTP) nextHTTP {
		return h.extractAuthorizeTokenAdmin(h.requireAPIEnabled(next))
	}

	requireEABEnabled := func(next nextHTTP) nextHTTP {
		return h.requireEABEnabled(next)
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

	// ACME External Account Binding Keys
	r.MethodFunc("GET", "/acme/eab/{provisionerName}/{reference}", authnz(requireEABEnabled(h.acmeResponder.GetExternalAccountKeys)))
	r.MethodFunc("GET", "/acme/eab/{provisionerName}", authnz(requireEABEnabled(h.acmeResponder.GetExternalAccountKeys)))
	r.MethodFunc("POST", "/acme/eab/{provisionerName}", authnz(requireEABEnabled(h.acmeResponder.CreateExternalAccountKey)))
	r.MethodFunc("DELETE", "/acme/eab/{provisionerName}/{id}", authnz(requireEABEnabled(h.acmeResponder.DeleteExternalAccountKey)))
}
