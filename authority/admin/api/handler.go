package api

import (
	"context"
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
)

var mustAuthority = func(ctx context.Context) adminAuthority {
	return authority.MustFromContext(ctx)
}

type router struct {
	acmeResponder    ACMEAdminResponder
	policyResponder  PolicyAdminResponder
	webhookResponder WebhookAdminResponder
}

type RouterOption func(*router)

func WithACMEResponder(acmeResponder ACMEAdminResponder) RouterOption {
	return func(r *router) {
		r.acmeResponder = acmeResponder
	}
}

func WithPolicyResponder(policyResponder PolicyAdminResponder) RouterOption {
	return func(r *router) {
		r.policyResponder = policyResponder
	}
}

func WithWebhookResponder(webhookResponder WebhookAdminResponder) RouterOption {
	return func(r *router) {
		r.webhookResponder = webhookResponder
	}
}

// Route traffic and implement the Router interface.
func Route(r api.Router, options ...RouterOption) {
	router := &router{}
	for _, fn := range options {
		fn(router)
	}

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

	webhookMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return authnz(loadProvisionerByName(next))
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
	if router.acmeResponder != nil {
		// ACME External Account Binding Keys
		r.MethodFunc("GET", "/acme/eab/{provisionerName}/{reference}", acmeEABMiddleware(router.acmeResponder.GetExternalAccountKeys))
		r.MethodFunc("GET", "/acme/eab/{provisionerName}", acmeEABMiddleware(router.acmeResponder.GetExternalAccountKeys))
		r.MethodFunc("POST", "/acme/eab/{provisionerName}", acmeEABMiddleware(router.acmeResponder.CreateExternalAccountKey))
		r.MethodFunc("DELETE", "/acme/eab/{provisionerName}/{id}", acmeEABMiddleware(router.acmeResponder.DeleteExternalAccountKey))
	}

	// Policy responder
	if router.policyResponder != nil {
		// Policy - Authority
		r.MethodFunc("GET", "/policy", authorityPolicyMiddleware(router.policyResponder.GetAuthorityPolicy))
		r.MethodFunc("POST", "/policy", authorityPolicyMiddleware(router.policyResponder.CreateAuthorityPolicy))
		r.MethodFunc("PUT", "/policy", authorityPolicyMiddleware(router.policyResponder.UpdateAuthorityPolicy))
		r.MethodFunc("DELETE", "/policy", authorityPolicyMiddleware(router.policyResponder.DeleteAuthorityPolicy))

		// Policy - Provisioner
		r.MethodFunc("GET", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(router.policyResponder.GetProvisionerPolicy))
		r.MethodFunc("POST", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(router.policyResponder.CreateProvisionerPolicy))
		r.MethodFunc("PUT", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(router.policyResponder.UpdateProvisionerPolicy))
		r.MethodFunc("DELETE", "/provisioners/{provisionerName}/policy", provisionerPolicyMiddleware(router.policyResponder.DeleteProvisionerPolicy))

		// Policy - ACME Account
		r.MethodFunc("GET", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(router.policyResponder.GetACMEAccountPolicy))
		r.MethodFunc("GET", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(router.policyResponder.GetACMEAccountPolicy))
		r.MethodFunc("POST", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(router.policyResponder.CreateACMEAccountPolicy))
		r.MethodFunc("POST", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(router.policyResponder.CreateACMEAccountPolicy))
		r.MethodFunc("PUT", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(router.policyResponder.UpdateACMEAccountPolicy))
		r.MethodFunc("PUT", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(router.policyResponder.UpdateACMEAccountPolicy))
		r.MethodFunc("DELETE", "/acme/policy/{provisionerName}/reference/{reference}", acmePolicyMiddleware(router.policyResponder.DeleteACMEAccountPolicy))
		r.MethodFunc("DELETE", "/acme/policy/{provisionerName}/key/{keyID}", acmePolicyMiddleware(router.policyResponder.DeleteACMEAccountPolicy))
	}

	if router.webhookResponder != nil {
		r.MethodFunc("POST", "/provisioners/{provisionerName}/webhooks", webhookMiddleware(router.webhookResponder.CreateProvisionerWebhook))
		r.MethodFunc("PUT", "/provisioners/{provisionerName}/webhooks/{webhookName}", webhookMiddleware(router.webhookResponder.UpdateProvisionerWebhook))
		r.MethodFunc("DELETE", "/provisioners/{provisionerName}/webhooks/{webhookName}", webhookMiddleware(router.webhookResponder.DeleteProvisionerWebhook))
	}
}
