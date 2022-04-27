package api

import (
	"context"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
)

// Handler is the Admin API request handler.
type Handler struct {
	acmeResponder acmeAdminResponderInterface
}

// Route traffic and implement the Router interface.
//
// Deprecated: use Route(r api.Router, acmeResponder acmeAdminResponderInterface)
func (h *Handler) Route(r api.Router) {
	Route(r, h.acmeResponder)
}

// NewHandler returns a new Authority Config Handler.
//
// Deprecated: use Route(r api.Router, acmeResponder acmeAdminResponderInterface)
func NewHandler(auth adminAuthority, adminDB admin.DB, acmeDB acme.DB, acmeResponder acmeAdminResponderInterface) api.RouterHandler {
	return &Handler{
		acmeResponder: acmeResponder,
	}
}

var mustAuthority = func(ctx context.Context) adminAuthority {
	return authority.MustFromContext(ctx)
}

// Route traffic and implement the Router interface.
func Route(r api.Router, acmeResponder acmeAdminResponderInterface) {
	authnz := func(next nextHTTP) nextHTTP {
		return extractAuthorizeTokenAdmin(requireAPIEnabled(next))
	}

	requireEABEnabled := func(next nextHTTP) nextHTTP {
		return requireEABEnabled(next)
	}

	// Provisioners
	r.MethodFunc("GET", "/provisioners/{name}", authnz(GetProvisioner))
	r.MethodFunc("GET", "/provisioners", authnz(GetProvisioners))
	r.MethodFunc("POST", "/provisioners", authnz(CreateProvisioner))
	r.MethodFunc("PUT", "/provisioners/{name}", authnz(UpdateProvisioner))
	r.MethodFunc("DELETE", "/provisioners/{name}", authnz(DeleteProvisioner))

	// Admins
	r.MethodFunc("GET", "/admins/{id}", authnz(GetAdmin))
	r.MethodFunc("GET", "/admins", authnz(GetAdmins))
	r.MethodFunc("POST", "/admins", authnz(CreateAdmin))
	r.MethodFunc("PATCH", "/admins/{id}", authnz(UpdateAdmin))
	r.MethodFunc("DELETE", "/admins/{id}", authnz(DeleteAdmin))

	// ACME External Account Binding Keys
	r.MethodFunc("GET", "/acme/eab/{provisionerName}/{reference}", authnz(requireEABEnabled(acmeResponder.GetExternalAccountKeys)))
	r.MethodFunc("GET", "/acme/eab/{provisionerName}", authnz(requireEABEnabled(acmeResponder.GetExternalAccountKeys)))
	r.MethodFunc("POST", "/acme/eab/{provisionerName}", authnz(requireEABEnabled(acmeResponder.CreateExternalAccountKey)))
	r.MethodFunc("DELETE", "/acme/eab/{provisionerName}/{id}", authnz(requireEABEnabled(acmeResponder.DeleteExternalAccountKey)))
}
