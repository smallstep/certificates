package api

import (
	"net/http"

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

	authnz := func(next http.HandlerFunc) http.HandlerFunc {
		return h.extractAuthorizeTokenAdmin(h.requireAPIEnabled(next))
	}

	requireEABEnabled := func(next http.HandlerFunc) http.HandlerFunc {
		return h.requireEABEnabled(next)
	}

	enabledInStandalone := func(next http.HandlerFunc) http.HandlerFunc {
		return h.checkAction(next, true)
	}

	disabledInStandalone := func(next http.HandlerFunc) http.HandlerFunc {
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
	r.MethodFunc("GET", "/acme/eab/{provisionerName}/{reference}", authnz(h.loadProvisionerByName(requireEABEnabled(h.acmeResponder.GetExternalAccountKeys))))
	r.MethodFunc("GET", "/acme/eab/{provisionerName}", authnz(h.loadProvisionerByName(requireEABEnabled(h.acmeResponder.GetExternalAccountKeys))))
	r.MethodFunc("POST", "/acme/eab/{provisionerName}", authnz(h.loadProvisionerByName(requireEABEnabled(h.acmeResponder.CreateExternalAccountKey))))
	r.MethodFunc("DELETE", "/acme/eab/{provisionerName}/{id}", authnz(h.loadProvisionerByName(requireEABEnabled(h.acmeResponder.DeleteExternalAccountKey))))

	// Policy - Authority
	r.MethodFunc("GET", "/policy", authnz(enabledInStandalone(h.policyResponder.GetAuthorityPolicy)))
	r.MethodFunc("POST", "/policy", authnz(enabledInStandalone(h.policyResponder.CreateAuthorityPolicy)))
	r.MethodFunc("PUT", "/policy", authnz(enabledInStandalone(h.policyResponder.UpdateAuthorityPolicy)))
	r.MethodFunc("DELETE", "/policy", authnz(enabledInStandalone(h.policyResponder.DeleteAuthorityPolicy)))

	// Policy - Provisioner
	r.MethodFunc("GET", "/provisioners/{provisionerName}/policy", authnz(disabledInStandalone(h.loadProvisionerByName(h.policyResponder.GetProvisionerPolicy))))
	r.MethodFunc("POST", "/provisioners/{provisionerName}/policy", authnz(disabledInStandalone(h.loadProvisionerByName(h.policyResponder.CreateProvisionerPolicy))))
	r.MethodFunc("PUT", "/provisioners/{provisionerName}/policy", authnz(disabledInStandalone(h.loadProvisionerByName(h.policyResponder.UpdateProvisionerPolicy))))
	r.MethodFunc("DELETE", "/provisioners/{provisionerName}/policy", authnz(disabledInStandalone(h.loadProvisionerByName(h.policyResponder.DeleteProvisionerPolicy))))

	// Policy - ACME Account
	r.MethodFunc("GET", "/acme/policy/{provisionerName}/{accountID}", authnz(disabledInStandalone(h.loadProvisionerByName(h.requireEABEnabled(h.policyResponder.GetACMEAccountPolicy)))))
	r.MethodFunc("POST", "/acme/policy/{provisionerName}/{accountID}", authnz(disabledInStandalone(h.loadProvisionerByName(h.requireEABEnabled(h.policyResponder.CreateACMEAccountPolicy)))))
	r.MethodFunc("PUT", "/acme/policy/{provisionerName}/{accountID}", authnz(disabledInStandalone(h.loadProvisionerByName(h.requireEABEnabled(h.policyResponder.UpdateACMEAccountPolicy)))))
	r.MethodFunc("DELETE", "/acme/policy/{provisionerName}/{accountID}", authnz(disabledInStandalone(h.loadProvisionerByName(h.requireEABEnabled(h.policyResponder.DeleteACMEAccountPolicy)))))
}
