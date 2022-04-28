package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
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
	// DB storage backend that impements the acme.DB interface.
	//
	// Deprecated: use acme.NewContex(context.Context, acme.DB)
	DB acme.DB

	// CA is the certificate authority interface.
	//
	// Deprecated: use authority.NewContext(context.Context, *authority.Authority)
	CA acme.CertificateAuthority

	// Backdate is the duration that the CA will substract from the current time
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

	linker                   Linker
	validateChallengeOptions *acme.ValidateChallengeOptions
}

type optionsKey struct{}

func newOptionsContext(ctx context.Context, o *HandlerOptions) context.Context {
	return context.WithValue(ctx, optionsKey{}, o)
}

func optionsFromContext(ctx context.Context) *HandlerOptions {
	o, ok := ctx.Value(optionsKey{}).(*HandlerOptions)
	if !ok {
		panic("acme options are not in the context")
	}
	return o
}

var mustAuthority = func(ctx context.Context) acme.CertificateAuthority {
	return authority.MustFromContext(ctx)
}

// Handler is the ACME API request handler.
type Handler struct {
	opts *HandlerOptions
}

// Route traffic and implement the Router interface.
//
// Deprecated: Use api.Route(r Router, opts *HandlerOptions)
func (h *Handler) Route(r api.Router) {
	Route(r, h.opts)
}

// NewHandler returns a new ACME API handler.
//
// Deprecated: Use api.Route(r Router, opts *HandlerOptions)
func NewHandler(ops HandlerOptions) api.RouterHandler {
	return &Handler{
		opts: &ops,
	}
}

// Route traffic and implement the Router interface.
func Route(r api.Router, opts *HandlerOptions) {
	// by default all prerequisites are met
	if opts.PrerequisitesChecker == nil {
		opts.PrerequisitesChecker = func(ctx context.Context) (bool, error) {
			return true, nil
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	opts.linker = NewLinker(opts.DNS, opts.Prefix)
	opts.validateChallengeOptions = &acme.ValidateChallengeOptions{
		HTTPGet:   client.Get,
		LookupTxt: net.LookupTXT,
		TLSDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, config)
		},
	}

	withOptions := func(next nextHTTP) nextHTTP {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// For backward compatibility with NewHandler.
			if ca, ok := opts.CA.(*authority.Authority); ok && ca != nil {
				ctx = authority.NewContext(ctx, ca)
			}
			if opts.DB != nil {
				ctx = acme.NewContext(ctx, opts.DB)
			}

			ctx = newOptionsContext(ctx, opts)
			next(w, r.WithContext(ctx))
		}
	}

	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return withOptions(baseURLFromRequest(lookupProvisioner(checkPrerequisites(addNonce(addDirLink(verifyContentType(parseJWS(validateJWS(next)))))))))
	}
	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return withOptions(validatingMiddleware(extractJWK(verifyAndExtractJWSPayload(next))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return withOptions(validatingMiddleware(lookupJWK(verifyAndExtractJWSPayload(next))))
	}
	extractPayloadByKidOrJWK := func(next nextHTTP) nextHTTP {
		return withOptions(validatingMiddleware(extractOrLookupJWK(verifyAndExtractJWSPayload(next))))
	}

	getPath := opts.linker.GetUnescapedPathSuffix

	// Standard ACME API
	r.MethodFunc("GET", getPath(NewNonceLinkType, "{provisionerID}"),
		withOptions(baseURLFromRequest(lookupProvisioner(checkPrerequisites(addNonce(addDirLink(GetNonce)))))))
	r.MethodFunc("HEAD", getPath(NewNonceLinkType, "{provisionerID}"),
		withOptions(baseURLFromRequest(lookupProvisioner(checkPrerequisites(addNonce(addDirLink(GetNonce)))))))
	r.MethodFunc("GET", getPath(DirectoryLinkType, "{provisionerID}"),
		withOptions(baseURLFromRequest(lookupProvisioner(checkPrerequisites(GetDirectory)))))
	r.MethodFunc("HEAD", getPath(DirectoryLinkType, "{provisionerID}"),
		withOptions(baseURLFromRequest(lookupProvisioner(checkPrerequisites(GetDirectory)))))

	r.MethodFunc("POST", getPath(NewAccountLinkType, "{provisionerID}"),
		extractPayloadByJWK(NewAccount))
	r.MethodFunc("POST", getPath(AccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(GetOrUpdateAccount))
	r.MethodFunc("POST", getPath(KeyChangeLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(NotImplemented))
	r.MethodFunc("POST", getPath(NewOrderLinkType, "{provisionerID}"),
		extractPayloadByKid(NewOrder))
	r.MethodFunc("POST", getPath(OrderLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(isPostAsGet(GetOrder)))
	r.MethodFunc("POST", getPath(OrdersByAccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(isPostAsGet(GetOrdersByAccountID)))
	r.MethodFunc("POST", getPath(FinalizeLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(FinalizeOrder))
	r.MethodFunc("POST", getPath(AuthzLinkType, "{provisionerID}", "{authzID}"),
		extractPayloadByKid(isPostAsGet(GetAuthorization)))
	r.MethodFunc("POST", getPath(ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"),
		extractPayloadByKid(GetChallenge))
	r.MethodFunc("POST", getPath(CertificateLinkType, "{provisionerID}", "{certID}"),
		extractPayloadByKid(isPostAsGet(GetCertificate)))
	r.MethodFunc("POST", getPath(RevokeCertLinkType, "{provisionerID}"),
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
	Meta       Meta   `json:"meta"`
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
	o := optionsFromContext(ctx)

	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	render.JSON(w, &Directory{
		NewNonce:   o.linker.GetLink(ctx, NewNonceLinkType),
		NewAccount: o.linker.GetLink(ctx, NewAccountLinkType),
		NewOrder:   o.linker.GetLink(ctx, NewOrderLinkType),
		RevokeCert: o.linker.GetLink(ctx, RevokeCertLinkType),
		KeyChange:  o.linker.GetLink(ctx, KeyChangeLinkType),
		Meta: Meta{
			ExternalAccountRequired: acmeProv.RequireEAB,
		},
	})
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func NotImplemented(w http.ResponseWriter, r *http.Request) {
	render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := optionsFromContext(ctx)
	db := acme.MustFromContext(ctx)

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

	o.linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", o.linker.GetLink(ctx, AuthzLinkType, az.ID))
	render.JSON(w, az)
}

// GetChallenge ACME api for retrieving a Challenge.
func GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := optionsFromContext(ctx)
	db := acme.MustFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	// Just verify that the payload was set, since we're not strictly adhering
	// to ACME V2 spec for reasons specified below.
	_, err = payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	// NOTE: We should be checking ^^^ that the request is either a POST-as-GET, or
	// that the payload is an empty JSON block ({}). However, older ACME clients
	// still send a vestigial body (rather than an empty JSON block) and
	// strict enforcement would render these clients broken. For the time being
	// we'll just ignore the body.

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
	if err = ch.Validate(ctx, db, jwk, o.validateChallengeOptions); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	o.linker.LinkChallenge(ctx, ch, azID)

	w.Header().Add("Link", link(o.linker.GetLink(ctx, AuthzLinkType, azID), "up"))
	w.Header().Set("Location", o.linker.GetLink(ctx, ChallengeLinkType, azID, ch.ID))
	render.JSON(w, ch)
}

// GetCertificate ACME api for retrieving a Certificate.
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustFromContext(ctx)

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
	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.Write(certBytes)
}
