package api

import (
	"context"
	"net/http"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
)

// Handler is the Admin API request handler.
type Handler struct {
	acmeResponder   ACMEAdminResponder
	policyResponder PolicyAdminResponder
}

// Route traffic and implement the Router interface.
//
// Deprecated: use Route(r api.Router, acmeResponder ACMEAdminResponder, policyResponder PolicyAdminResponder)
func (h *Handler) Route(r api.Router) {
	Route(r, h.acmeResponder, h.policyResponder)
}

// NewHandler returns a new Authority Config Handler.
//
// Deprecated: use Route(r api.Router, acmeResponder ACMEAdminResponder, policyResponder PolicyAdminResponder)
func NewHandler(auth adminAuthority, adminDB admin.DB, acmeDB acme.DB, acmeResponder ACMEAdminResponder, policyResponder PolicyAdminResponder) api.RouterHandler {
	return &Handler{
		acmeResponder:   acmeResponder,
		policyResponder: policyResponder,
	}
}

var mustAuthority = func(ctx context.Context) adminAuthority {
	return authority.MustFromContext(ctx)
}

// Route traffic and implement the Router interface.
func Route(r api.Router, acmeResponder ACMEAdminResponder, policyResponder PolicyAdminResponder) {
	authnz := func(next http.HandlerFunc) http.HandlerFunc {
		return extractAuthorizeTokenAdmin(requireAPIEnabled(next))
	}

	enabledInStandalone := func(next http.HandlerFunc) http.HandlerFunc {
		return checkAction(next, true)
	}

	disabledInStandalone := func(next http.HandlerFunc) http.HandlerFunc {
		return checkAction(next, false)
	}

	acmeEABMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return authnz(loadProvisionerByName(requireEABEnabled(next)))
	}

	authorityPolicyMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return authnz(enabledInStandalone(next))
	}

	provisionerPolicyMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return authnz(disabledInStandalone(loadProvisionerByName(next)))
	}

	acmePolicyMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return authnz(disabledInStandalone(loadProvisionerByName(requireEABEnabled(loadExternalAccountKey(next)))))
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

	// ACME responder
	if acmeResponder != nil {
		// ACME External Account Binding Keys
		r.MethodFunc("GET", "/acme/eab/{provisionerName}/{reference}", acmeEABMiddleware(acmeResponder.GetExternalAccountKeys))
		r.MethodFunc("GET", "/acme/eab/{provisionerName}", acmeEABMiddleware(acmeResponder.GetExternalAccountKeys))
		r.MethodFunc("POST", "/acme/eab/{provisionerName}", acmeEABMiddleware(acmeResponder.CreateExternalAccountKey))
		r.MethodFunc("DELETE", "/acme/eab/{provisionerName}/{id}", acmeEABMiddleware(acmeResponder.DeleteExternalAccountKey))
	}

	// Policy responder
	if policyResponder != nil {
		// Policy - Authority
		r.MethodFunc("GET", "/policy", authorityPolicyMiddleware(policyResponder.GetAuthorityPolicy))
		r.MethodFunc("POST", "/policy", authorityPolicyMiddleware(policyResponder.CreateAuthorityPolicy))
		r.MethodFunc("PUT", "/policy", authorityPolicyMiddleware(policyResponder.UpdateAuthorityPolicy))
		r.MethodFunc("DELETE", "/policy", authorityPolicyMiddleware(policyResponder.DeleteAuthorityPolicy))

		// Policy - Provisioner
		r.MethodFunc("GET", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(policyResponder.GetProvisionerPolicy))
		r.MethodFunc("POST", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(policyResponder.CreateProvisionerPolicy))
		r.MethodFunc("PUT", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(policyResponder.UpdateProvisionerPolicy))
		r.MethodFunc("DELETE", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(policyResponder.DeleteProvisionerPolicy))

		// Policy - ACME Account
		r.MethodFunc("GET", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(policyResponder.GetACMEAccountPolicy))
		r.MethodFunc("GET", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(policyResponder.GetACMEAccountPolicy))
		r.MethodFunc("POST", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(policyResponder.CreateACMEAccountPolicy))
		r.MethodFunc("POST", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(policyResponder.CreateACMEAccountPolicy))
		r.MethodFunc("PUT", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(policyResponder.UpdateACMEAccountPolicy))
		r.MethodFunc("PUT", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(policyResponder.UpdateACMEAccountPolicy))
		r.MethodFunc("DELETE", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(policyResponder.DeleteACMEAccountPolicy))
		r.MethodFunc("DELETE", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(policyResponder.DeleteACMEAccountPolicy))
	}
}
