package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/provisioner"
)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func requireAPIEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !mustAuthority(r.Context()).IsAdminAPIEnabled() {
			render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "administration API not enabled"))
			return
		}
		next(w, r)
	}
}

// extractAuthorizeTokenAdmin is a middleware that extracts and caches the bearer token.
func extractAuthorizeTokenAdmin(next http.HandlerFunc) http.HandlerFunc {
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

		ctx = linkedca.NewContextWithAdmin(ctx, adm)
		next(w, r.WithContext(ctx))
	}
}

// loadProvisionerByName is a middleware that searches for a provisioner
// by name and stores it in the context.
func loadProvisionerByName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			p   provisioner.Interface
			err error
		)

		ctx := r.Context()
		auth := mustAuthority(ctx)
		adminDB := admin.MustFromContext(ctx)
		name := chi.URLParam(r, "provisionerName")

		// TODO(hs): distinguish 404 vs. 500
		if p, err = auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}

		prov, err := adminDB.GetProvisioner(ctx, p.GetID())
		if err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error retrieving provisioner %s", name))
			return
		}

		ctx = linkedca.NewContextWithProvisioner(ctx, prov)
		next(w, r.WithContext(ctx))
	}
}

// checkAction checks if an action is supported in standalone or not
func checkAction(next http.HandlerFunc, supportedInStandalone bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// actions allowed in standalone mode are always supported
		if supportedInStandalone {
			next(w, r)
			return
		}

		// when an action is not supported in standalone mode and when
		// using a nosql.DB backend, actions are not supported
		if _, ok := admin.MustFromContext(r.Context()).(*nosql.DB); ok {
			render.Error(w, admin.NewError(admin.ErrorNotImplementedType,
				"operation not supported in standalone mode"))
			return
		}

		// continue to next http handler
		next(w, r)
	}
}

// loadExternalAccountKey is a middleware that searches for an ACME
// External Account Key by reference or keyID and stores it in the context.
func loadExternalAccountKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.MustProvisionerFromContext(ctx)
		acmeDB := acme.MustDatabaseFromContext(ctx)

		reference := chi.URLParam(r, "reference")
		keyID := chi.URLParam(r, "keyID")

		var (
			eak *acme.ExternalAccountKey
			err error
		)

		if keyID != "" {
			eak, err = acmeDB.GetExternalAccountKey(ctx, prov.GetId(), keyID)
		} else {
			eak, err = acmeDB.GetExternalAccountKeyByReference(ctx, prov.GetId(), reference)
		}

		if err != nil {
			if errors.Is(err, acme.ErrNotFound) {
				render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found"))
				return
			}
			render.Error(w, admin.WrapErrorISE(err, "error retrieving ACME External Account Key"))
			return
		}

		if eak == nil {
			render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found"))
			return
		}

		linkedEAK := eakToLinked(eak)

		ctx = linkedca.NewContextWithExternalAccountKey(ctx, linkedEAK)

		next(w, r.WithContext(ctx))
	}
}
