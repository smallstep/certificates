package api

import (
	"context"
	"net/http"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func requireAPIEnabled(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		if !mustAuthority(r.Context()).IsAdminAPIEnabled() {
			render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "administration API not enabled"))
			return
		}
		next(w, r)
	}
}

// extractAuthorizeTokenAdmin is a middleware that extracts and caches the bearer token.
func extractAuthorizeTokenAdmin(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			render.Error(w, admin.NewError(admin.ErrorUnauthorizedType,
				"missing authorization header token"))
			return
		}

		ctx := r.Context()
		adm, err := mustAuthority(ctx).AuthorizeAdminToken(r, tok)
		if err != nil {
			render.Error(w, err)
			return
		}

		ctx = context.WithValue(ctx, adminContextKey, adm)
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
