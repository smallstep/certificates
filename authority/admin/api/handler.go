package api

import (
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
)

// Handler is the Admin API request handler.
type Handler struct {
	adminDB         admin.DB
	auth            adminAuthority
	acmeDB          acme.DB
	acmeResponder   acmeAdminResponderInterface
	policyResponder policyAdminResponderInterface
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(auth adminAuthority, adminDB admin.DB, acmeDB acme.DB, acmeResponder acmeAdminResponderInterface, policyResponder policyAdminResponderInterface) api.RouterHandler {
	return &Handler{
		auth:            auth,
		adminDB:         adminDB,
		acmeDB:          acmeDB,
		acmeResponder:   acmeResponder,
		policyResponder: policyResponder,
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

	enabledInStandalone := func(next nextHTTP) nextHTTP {
		return h.checkAction(next, true)
	}

	disabledInStandalone := func(next nextHTTP) nextHTTP {
		return h.checkAction(next, false)
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

	// Policy - Authority
	r.MethodFunc("GET", "/policy", authnz(enabledInStandalone(h.policyResponder.GetAuthorityPolicy)))
	r.MethodFunc("POST", "/policy", authnz(enabledInStandalone(h.policyResponder.CreateAuthorityPolicy)))
	r.MethodFunc("PUT", "/policy", authnz(enabledInStandalone(h.policyResponder.UpdateAuthorityPolicy)))
	r.MethodFunc("DELETE", "/policy", authnz(enabledInStandalone(h.policyResponder.DeleteAuthorityPolicy)))

	// Policy - Provisioner
	//r.MethodFunc("GET", "/provisioners/{name}/policy", noauth(h.policyResponder.GetProvisionerPolicy))
	r.MethodFunc("GET", "/provisioners/{name}/policy", authnz(disabledInStandalone(h.policyResponder.GetProvisionerPolicy)))
	r.MethodFunc("POST", "/provisioners/{name}/policy", authnz(disabledInStandalone(h.policyResponder.CreateProvisionerPolicy)))
	r.MethodFunc("PUT", "/provisioners/{name}/policy", authnz(disabledInStandalone(h.policyResponder.UpdateProvisionerPolicy)))
	r.MethodFunc("DELETE", "/provisioners/{name}/policy", authnz(disabledInStandalone(h.policyResponder.DeleteProvisionerPolicy)))

	// Policy - ACME Account
	// TODO: ensure we don't clash with eab; might want to change eab paths slightly (as long as we don't have it released completely; needs changes in adminClient too)
	r.MethodFunc("GET", "/acme/{provisionerName}/{accountID}/policy", authnz(disabledInStandalone(h.policyResponder.GetACMEAccountPolicy)))
	r.MethodFunc("POST", "/acme/{provisionerName}/{accountID}/policy", authnz(disabledInStandalone(h.policyResponder.CreateACMEAccountPolicy)))
	r.MethodFunc("PUT", "/acme/{provisionerName}/{accountID}/policy", authnz(disabledInStandalone(h.policyResponder.UpdateACMEAccountPolicy)))
	r.MethodFunc("DELETE", "/acme/{provisionerName}/{accountID}/policy", authnz(disabledInStandalone(h.policyResponder.DeleteACMEAccountPolicy)))
}
