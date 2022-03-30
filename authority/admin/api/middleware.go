package api

import (
	"net/http"

	"go.step.sm/linkedca"

	"github.com/go-chi/chi"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/provisioner"
)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func (h *Handler) requireAPIEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.auth.IsAdminAPIEnabled() {
			api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType,
				"administration API not enabled"))
			return
		}
		next(w, r)
	}
}

// extractAuthorizeTokenAdmin is a middleware that extracts and caches the bearer token.
func (h *Handler) extractAuthorizeTokenAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tok := r.Header.Get("Authorization")
		if tok == "" {
			api.WriteError(w, admin.NewError(admin.ErrorUnauthorizedType,
				"missing authorization header token"))
			return
		}

		adm, err := h.auth.AuthorizeAdminToken(r, tok)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		ctx := linkedca.NewContextWithAdmin(r.Context(), adm)
		next(w, r.WithContext(ctx))
	}
}

// loadProvisioner is a middleware that searches for a provisioner
// by name and stores it in the context.
func (h *Handler) loadProvisionerByName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		name := chi.URLParam(r, "provisionerName")
		var (
			p   provisioner.Interface
			err error
		)
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}

		prov, err := h.adminDB.GetProvisioner(ctx, p.GetID())
		if err != nil {
			api.WriteError(w, err)
			return
		}

		ctx = linkedca.NewContextWithProvisioner(ctx, prov)
		next(w, r.WithContext(ctx))
	}
}

// checkAction checks if an action is supported in standalone or not
func (h *Handler) checkAction(next http.HandlerFunc, supportedInStandalone bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// actions allowed in standalone mode are always supported
		if supportedInStandalone {
			next(w, r)
			return
		}

		// when an action is not supported in standalone mode and when
		// using a nosql.DB backend, actions are not supported
		if _, ok := h.adminDB.(*nosql.DB); ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType,
				"operation not supported in standalone mode"))
			return
		}

		// continue to next http handler
		next(w, r)
	}
}
