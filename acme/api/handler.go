package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=%q", url, typ)
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

// HandlerOptions required to create a new ACME API request handler.
type HandlerOptions struct {
	// DB storage backend that implements the acme.DB interface.
	//
	// Deprecated: use acme.NewContex(context.Context, acme.DB)
	DB acme.DB

	// CA is the certificate authority interface.
	//
	// Deprecated: use authority.NewContext(context.Context, *authority.Authority)
	CA acme.CertificateAuthority

	// Backdate is the duration that the CA will subtract from the current time
	// to set the NotBefore in the certificate.
	Backdate provisioner.Duration

	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string

	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string

	// PrerequisitesChecker checks if all prerequisites for serving ACME are
	// met by the CA configuration.
	PrerequisitesChecker func(ctx context.Context) (bool, error)
}

var mustAuthority = func(ctx context.Context) acme.CertificateAuthority {
	return authority.MustFromContext(ctx)
}

// handler is the ACME API request handler.
type handler struct {
	opts *HandlerOptions
}

// Route traffic and implement the Router interface. For backward compatibility
// this route adds will add a new middleware that will set the ACME components
// on the context.
//
// Note: this method is deprecated in step-ca, other applications can still use
// this to support ACME, but the recommendation is to use use
// api.Route(api.Router) and acme.NewContext() instead.
func (h *handler) Route(r api.Router) {
	client := acme.NewClient()
	linker := acme.NewLinker(h.opts.DNS, h.opts.Prefix)
	route(r, func(next nextHTTP) nextHTTP {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if ca, ok := h.opts.CA.(*authority.Authority); ok && ca != nil {
				ctx = authority.NewContext(ctx, ca)
			}
			ctx = acme.NewContext(ctx, h.opts.DB, client, linker, h.opts.PrerequisitesChecker)
			next(w, r.WithContext(ctx))
		}
	})
}

// NewHandler returns a new ACME API handler.
//
// Note: this method is deprecated in step-ca, other applications can still use
// this to support ACME, but the recommendation is to use use
// api.Route(api.Router) and acme.NewContext() instead.
func NewHandler(opts HandlerOptions) api.RouterHandler {
	return &handler{
		opts: &opts,
	}
}

// Route traffic and implement the Router interface. This method requires that
// all the acme components, authority, db, client, linker, and prerequisite
// checker to be present in the context.
func Route(r api.Router) {
	route(r, nil)
}

func route(r api.Router, middleware func(next nextHTTP) nextHTTP) {
	commonMiddleware := func(next nextHTTP) nextHTTP {
		handler := func(w http.ResponseWriter, r *http.Request) {
			// Linker middleware gets the provisioner and current url from the
			// request and sets them in the context.
			linker := acme.MustLinkerFromContext(r.Context())
			linker.Middleware(http.HandlerFunc(checkPrerequisites(next))).ServeHTTP(w, r)
		}
		if middleware != nil {
			handler = middleware(handler)
		}
		return handler
	}
	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return commonMiddleware(addNonce(addDirLink(verifyContentType(parseJWS(validateJWS(next))))))
	}
	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(lookupJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKidOrJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractOrLookupJWK(verifyAndExtractJWSPayload(next)))
	}

	getPath := acme.GetUnescapedPathSuffix

	// Standard ACME API
	r.MethodFunc("GET", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))
	r.MethodFunc("HEAD", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))
	r.MethodFunc("GET", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))
	r.MethodFunc("HEAD", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))

	r.MethodFunc("POST", getPath(acme.NewAccountLinkType, "{provisionerID}"),
		extractPayloadByJWK(NewAccount))
	r.MethodFunc("POST", getPath(acme.AccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(GetOrUpdateAccount))
	r.MethodFunc("POST", getPath(acme.KeyChangeLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(NotImplemented))
	r.MethodFunc("POST", getPath(acme.NewOrderLinkType, "{provisionerID}"),
		extractPayloadByKid(NewOrder))
	r.MethodFunc("POST", getPath(acme.OrderLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(isPostAsGet(GetOrder)))
	r.MethodFunc("POST", getPath(acme.OrdersByAccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(isPostAsGet(GetOrdersByAccountID)))
	r.MethodFunc("POST", getPath(acme.FinalizeLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(FinalizeOrder))
	r.MethodFunc("POST", getPath(acme.AuthzLinkType, "{provisionerID}", "{authzID}"),
		extractPayloadByKid(isPostAsGet(GetAuthorization)))
	r.MethodFunc("POST", getPath(acme.ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"),
		extractPayloadByKid(GetChallenge))
	r.MethodFunc("POST", getPath(acme.CertificateLinkType, "{provisionerID}", "{certID}"),
		extractPayloadByKid(isPostAsGet(GetCertificate)))
	r.MethodFunc("POST", getPath(acme.RevokeCertLinkType, "{provisionerID}"),
		extractPayloadByKidOrJWK(RevokeCert))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       *Meta  `json:"meta,omitempty"`
}

// ToLog enables response logging for the Directory type.
func (d *Directory) ToLog() (interface{}, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling directory for logging")
	}
	return string(b), nil
}

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func GetDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	linker := acme.MustLinkerFromContext(ctx)

	render.JSON(w, &Directory{
		NewNonce:   linker.GetLink(ctx, acme.NewNonceLinkType),
		NewAccount: linker.GetLink(ctx, acme.NewAccountLinkType),
		NewOrder:   linker.GetLink(ctx, acme.NewOrderLinkType),
		RevokeCert: linker.GetLink(ctx, acme.RevokeCertLinkType),
		KeyChange:  linker.GetLink(ctx, acme.KeyChangeLinkType),
		Meta:       createMetaObject(acmeProv),
	})
}

// createMetaObject creates a Meta object if the ACME provisioner
// has one or more properties that are written in the ACME directory output.
// It returns nil if none of the properties are set.
func createMetaObject(p *provisioner.ACME) *Meta {
	if shouldAddMetaObject(p) {
		return &Meta{
			TermsOfService:          p.TermsOfService,
			Website:                 p.Website,
			CaaIdentities:           p.CaaIdentities,
			ExternalAccountRequired: p.RequireEAB,
		}
	}
	return nil
}

// shouldAddMetaObject returns whether or not the ACME provisioner
// has properties configured that must be added to the ACME directory object.
func shouldAddMetaObject(p *provisioner.ACME) bool {
	switch {
	case p.TermsOfService != "":
		return true
	case p.Website != "":
		return true
	case len(p.CaaIdentities) > 0:
		return true
	case p.RequireEAB:
		return true
	default:
		return false
	}
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func NotImplemented(w http.ResponseWriter, r *http.Request) {
	render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	az, err := db.GetAuthorization(ctx, chi.URLParam(r, "authzID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving authorization"))
		return
	}
	if acc.ID != az.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID))
		return
	}
	if err = az.UpdateStatus(ctx, db); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error updating authorization status"))
		return
	}

	linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", linker.GetLink(ctx, acme.AuthzLinkType, az.ID))
	render.JSON(w, az)
}

// GetChallenge ACME api for retrieving a Challenge.
func GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	// NOTE: We should be checking that the request is either a POST-as-GET, or
	// that for all challenges except for device-attest-01, the payload is an
	// empty JSON block ({}). However, older ACME clients still send a vestigial
	// body (rather than an empty JSON block) and strict enforcement would
	// render these clients broken.

	azID := chi.URLParam(r, "authzID")
	ch, err := db.GetChallenge(ctx, chi.URLParam(r, "chID"), azID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving challenge"))
		return
	}
	ch.AuthorizationID = azID
	if acc.ID != ch.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own challenge '%s'", acc.ID, ch.ID))
		return
	}
	jwk, err := jwkFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	if err = ch.Validate(ctx, db, jwk, payload.value); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	linker.LinkChallenge(ctx, ch, azID)

	w.Header().Add("Link", link(linker.GetLink(ctx, acme.AuthzLinkType, azID), "up"))
	w.Header().Set("Location", linker.GetLink(ctx, acme.ChallengeLinkType, azID, ch.ID))
	render.JSON(w, ch)
}

// GetCertificate ACME api for retrieving a Certificate.
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	certID := chi.URLParam(r, "certID")
	cert, err := db.GetCertificate(ctx, certID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving certificate"))
		return
	}
	if cert.AccountID != acc.ID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own certificate '%s'", acc.ID, certID))
		return
	}

	var certBytes []byte
	for _, c := range append([]*x509.Certificate{cert.Leaf}, cert.Intermediates...) {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	api.LogCertificate(w, cert.Leaf)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(certBytes)
}
