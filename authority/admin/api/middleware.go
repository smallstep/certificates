package api

import (
	"context"
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
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

		ctx := context.WithValue(r.Context(), adminContextKey, adm)
		next(w, r.WithContext(ctx))
	}
}

// ContextKey is the key type for storing and searching for ACME request
// essentials in the context of a request.
type ContextKey string

const (
	// adminContextKey account key
	adminContextKey = ContextKey("admin")
)
