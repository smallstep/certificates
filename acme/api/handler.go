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

// Handler is the ACME API request handler.
type Handler struct {
	db                       acme.DB
	backdate                 provisioner.Duration
	ca                       acme.CertificateAuthority
	linker                   Linker
	validateChallengeOptions *acme.ValidateChallengeOptions
	prerequisitesChecker     func(ctx context.Context) (bool, error)
}

// HandlerOptions required to create a new ACME API request handler.
type HandlerOptions struct {
	Backdate provisioner.Duration
	// DB storage backend that impements the acme.DB interface.
	DB acme.DB
	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string
	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string
	CA     acme.CertificateAuthority
	// PrerequisitesChecker checks if all prerequisites for serving ACME are
	// met by the CA configuration.
	PrerequisitesChecker func(ctx context.Context) (bool, error)
}

// NewHandler returns a new ACME API handler.
func NewHandler(ops HandlerOptions) api.RouterHandler {
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
	prerequisitesChecker := func(ctx context.Context) (bool, error) {
		// by default all prerequisites are met
		return true, nil
	}
	if ops.PrerequisitesChecker != nil {
		prerequisitesChecker = ops.PrerequisitesChecker
	}
	return &Handler{
		ca:       ops.CA,
		db:       ops.DB,
		backdate: ops.Backdate,
		linker:   NewLinker(ops.DNS, ops.Prefix),
		validateChallengeOptions: &acme.ValidateChallengeOptions{
			HTTPGet:   client.Get,
			LookupTxt: net.LookupTXT,
			TLSDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
				return tls.DialWithDialer(dialer, network, addr, config)
			},
		},
		prerequisitesChecker: prerequisitesChecker,
	}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	getPath := h.linker.GetUnescapedPathSuffix
	// Standard ACME API
	r.MethodFunc("GET", getPath(NewNonceLinkType, "{provisionerID}"), h.baseURLFromRequest(h.lookupProvisioner(h.checkPrerequisites(h.addNonce(h.addDirLink(h.GetNonce))))))
	r.MethodFunc("HEAD", getPath(NewNonceLinkType, "{provisionerID}"), h.baseURLFromRequest(h.lookupProvisioner(h.checkPrerequisites(h.addNonce(h.addDirLink(h.GetNonce))))))
	r.MethodFunc("GET", getPath(DirectoryLinkType, "{provisionerID}"), h.baseURLFromRequest(h.lookupProvisioner(h.checkPrerequisites(h.GetDirectory))))
	r.MethodFunc("HEAD", getPath(DirectoryLinkType, "{provisionerID}"), h.baseURLFromRequest(h.lookupProvisioner(h.checkPrerequisites(h.GetDirectory))))

	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return h.baseURLFromRequest(h.lookupProvisioner(h.checkPrerequisites(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(next))))))))
	}
	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(h.extractJWK(h.verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(h.lookupJWK(h.verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKidOrJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(h.extractOrLookupJWK(h.verifyAndExtractJWSPayload(next)))
	}

	r.MethodFunc("POST", getPath(NewAccountLinkType, "{provisionerID}"), extractPayloadByJWK(h.NewAccount))
	r.MethodFunc("POST", getPath(AccountLinkType, "{provisionerID}", "{accID}"), extractPayloadByKid(h.GetOrUpdateAccount))
	r.MethodFunc("POST", getPath(KeyChangeLinkType, "{provisionerID}", "{accID}"), extractPayloadByKid(h.NotImplemented))
	r.MethodFunc("POST", getPath(NewOrderLinkType, "{provisionerID}"), extractPayloadByKid(h.NewOrder))
	r.MethodFunc("POST", getPath(OrderLinkType, "{provisionerID}", "{ordID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrder)))
	r.MethodFunc("POST", getPath(OrdersByAccountLinkType, "{provisionerID}", "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrdersByAccountID)))
	r.MethodFunc("POST", getPath(FinalizeLinkType, "{provisionerID}", "{ordID}"), extractPayloadByKid(h.FinalizeOrder))
	r.MethodFunc("POST", getPath(AuthzLinkType, "{provisionerID}", "{authzID}"), extractPayloadByKid(h.isPostAsGet(h.GetAuthorization)))
	r.MethodFunc("POST", getPath(ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"), extractPayloadByKid(h.GetChallenge))
	r.MethodFunc("POST", getPath(CertificateLinkType, "{provisionerID}", "{certID}"), extractPayloadByKid(h.isPostAsGet(h.GetCertificate)))
	r.MethodFunc("POST", getPath(RevokeCertLinkType, "{provisionerID}"), extractPayloadByKidOrJWK(h.RevokeCert))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func (h *Handler) GetNonce(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	render.JSON(w, &Directory{
		NewNonce:   h.linker.GetLink(ctx, NewNonceLinkType),
		NewAccount: h.linker.GetLink(ctx, NewAccountLinkType),
		NewOrder:   h.linker.GetLink(ctx, NewOrderLinkType),
		RevokeCert: h.linker.GetLink(ctx, RevokeCertLinkType),
		KeyChange:  h.linker.GetLink(ctx, KeyChangeLinkType),
		Meta: Meta{
			ExternalAccountRequired: acmeProv.RequireEAB,
		},
	})
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func (h *Handler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func (h *Handler) GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	az, err := h.db.GetAuthorization(ctx, chi.URLParam(r, "authzID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving authorization"))
		return
	}
	if acc.ID != az.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID))
		return
	}
	if err = az.UpdateStatus(ctx, h.db); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error updating authorization status"))
		return
	}

	h.linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", h.linker.GetLink(ctx, AuthzLinkType, az.ID))
	render.JSON(w, az)
}

// GetChallenge ACME api for retrieving a Challenge.
func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	ch, err := h.db.GetChallenge(ctx, chi.URLParam(r, "chID"), azID)
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
	if err = ch.Validate(ctx, h.db, jwk, h.validateChallengeOptions); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	h.linker.LinkChallenge(ctx, ch, azID)

	w.Header().Add("Link", link(h.linker.GetLink(ctx, AuthzLinkType, azID), "up"))
	w.Header().Set("Location", h.linker.GetLink(ctx, ChallengeLinkType, azID, ch.ID))
	render.JSON(w, ch)
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	certID := chi.URLParam(r, "certID")

	cert, err := h.db.GetCertificate(ctx, certID)
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
