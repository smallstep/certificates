package api

import (
	"context"
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/db/nosql"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func (h *Handler) requireAPIEnabled(next nextHTTP) nextHTTP {
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
func (h *Handler) extractAuthorizeTokenAdmin(next nextHTTP) nextHTTP {
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

		ctx := linkedca.WithAdmin(r.Context(), adm)
		next(w, r.WithContext(ctx))
	}
}

// checkAction checks if an action is supported in standalone or not
func (h *Handler) checkAction(next nextHTTP, supportedInStandalone bool) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

		// actions allowed in standalone mode are always supported
		if supportedInStandalone {
			next(w, r)
			return
		}

		// when not in standalone mode and using a nosql.DB backend,
		// actions are not supported
		if _, ok := h.adminDB.(*nosql.DB); ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType,
				"operation not supported in standalone mode"))
			return
		}

		// continue to next http handler
		next(w, r)
	}
}

// adminFromContext searches the context for a *linkedca.Admin.
// Returns the admin or an error.
func adminFromContext(ctx context.Context) (*linkedca.Admin, error) {
	val, ok := ctx.Value(admin.AdminContextKey).(*linkedca.Admin)
	if !ok || val == nil {
		return nil, admin.NewError(admin.ErrorBadRequestType, "admin not in context")
	}
	return val, nil
}
