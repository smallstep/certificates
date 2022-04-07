package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/provisioner"
)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func (h *Handler) requireAPIEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.auth.IsAdminAPIEnabled() {
			render.Error(w, admin.NewError(admin.ErrorNotImplementedType,
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
			render.Error(w, admin.NewError(admin.ErrorUnauthorizedType,
				"missing authorization header token"))
			return
		}

		adm, err := h.auth.AuthorizeAdminToken(r, tok)
		if err != nil {
			render.Error(w, err)
			return
		}

		ctx := linkedca.NewContextWithAdmin(r.Context(), adm)
		next(w, r.WithContext(ctx))
	}
}

// loadProvisionerByName is a middleware that searches for a provisioner
// by name and stores it in the context.
func (h *Handler) loadProvisionerByName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		name := chi.URLParam(r, "provisionerName")
		var (
			p   provisioner.Interface
			err error
		)

		// TODO(hs): distinguish 404 vs. 500
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}

		prov, err := h.adminDB.GetProvisioner(ctx, p.GetID())
		if err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error retrieving provisioner %s", name))
			return
		}

		ctx = linkedca.NewContextWithProvisioner(ctx, prov)
		next(w, r.WithContext(ctx))
	}
}

// checkAction checks if an action is supported in standalone or not
func (h *Handler) checkAction(next http.HandlerFunc, supportedInStandalone bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// // temporarily only support the admin nosql DB
		// if _, ok := h.adminDB.(*nosql.DB); !ok {
		// 	render.Error(w, admin.NewError(admin.ErrorNotImplementedType,
		// 		"operation not supported"))
		// 	return
		// }

		// actions allowed in standalone mode are always supported
		if supportedInStandalone {
			next(w, r)
			return
		}

		// when an action is not supported in standalone mode and when
		// using a nosql.DB backend, actions are not supported
		if _, ok := h.adminDB.(*nosql.DB); ok {
			render.Error(w, admin.NewError(admin.ErrorNotImplementedType,
				"operation not supported in standalone mode"))
			return
		}

		// continue to next http handler
		next(w, r)
	}
}

// loadExternalAccountKey is a middleware that searches for an ACME
// External Account Key by accountID, keyID or reference and stores it in the context.
func (h *Handler) loadExternalAccountKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.ProvisionerFromContext(ctx)

		reference := chi.URLParam(r, "reference")
		keyID := chi.URLParam(r, "keyID")

		var (
			eak *acme.ExternalAccountKey
			err error
		)

		if keyID != "" {
			eak, err = h.acmeDB.GetExternalAccountKey(ctx, prov.GetId(), keyID)
		} else {
			eak, err = h.acmeDB.GetExternalAccountKeyByReference(ctx, prov.GetId(), reference)
		}

		if err != nil {
			// TODO: handle error; not found vs. some internal server error
			render.Error(w, admin.WrapErrorISE(err, "error retrieving ACME External Account key"))
			return
		}

		if eak == nil {
			render.Error(w, admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key does not exist"))
			return
		}

		linkedEAK := eakToLinked(eak)

		ctx = linkedca.NewContextWithExternalAccountKey(ctx, linkedEAK)

		next(w, r.WithContext(ctx))
	}
}

func eakToLinked(k *acme.ExternalAccountKey) *linkedca.EABKey {

	if k == nil {
		return nil
	}

	eak := &linkedca.EABKey{
		Id:          k.ID,
		HmacKey:     k.KeyBytes,
		Provisioner: k.ProvisionerID,
		Reference:   k.Reference,
		Account:     k.AccountID,
		CreatedAt:   timestamppb.New(k.CreatedAt),
		BoundAt:     timestamppb.New(k.BoundAt),
	}

	if k.Policy != nil {
		eak.Policy = &linkedca.Policy{
			X509: &linkedca.X509Policy{
				Allow: &linkedca.X509Names{},
				Deny:  &linkedca.X509Names{},
			},
		}
		eak.Policy.X509.Allow.Dns = k.Policy.X509.Allowed.DNSNames
		eak.Policy.X509.Allow.Ips = k.Policy.X509.Allowed.IPRanges
		eak.Policy.X509.Deny.Dns = k.Policy.X509.Denied.DNSNames
		eak.Policy.X509.Deny.Ips = k.Policy.X509.Denied.IPRanges
	}

	return eak
}

func linkedEAKToCertificates(k *linkedca.EABKey) *acme.ExternalAccountKey {
	if k == nil {
		return nil
	}

	eak := &acme.ExternalAccountKey{
		ID:            k.Id,
		ProvisionerID: k.Provisioner,
		Reference:     k.Reference,
		AccountID:     k.Account,
		KeyBytes:      k.HmacKey,
		CreatedAt:     k.CreatedAt.AsTime(),
		BoundAt:       k.BoundAt.AsTime(),
	}

	if k.Policy == nil {
		return eak
	}

	eak.Policy = &acme.Policy{}

	if k.Policy.X509 == nil {
		return eak
	}

	eak.Policy.X509 = acme.X509Policy{
		Allowed: acme.PolicyNames{},
		Denied:  acme.PolicyNames{},
	}

	if k.Policy.X509.Allow != nil {
		eak.Policy.X509.Allowed.DNSNames = k.Policy.X509.Allow.Dns
		eak.Policy.X509.Allowed.IPRanges = k.Policy.X509.Allow.Ips
	}

	if k.Policy.X509.Deny != nil {
		eak.Policy.X509.Denied.DNSNames = k.Policy.X509.Deny.Dns
		eak.Policy.X509.Denied.IPRanges = k.Policy.X509.Deny.Ips
	}

	return eak
}
