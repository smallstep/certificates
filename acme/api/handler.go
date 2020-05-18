package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, typ)
}

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

// payloadFromContext searches the context for a payload. Returns the payload
// or an error.
func payloadFromContext(ctx context.Context) (*payloadInfo, error) {
	val, ok := ctx.Value(acme.PayloadContextKey).(*payloadInfo)
	if !ok || val == nil {
		return nil, acme.ServerInternalErr(errors.Errorf("payload expected in request context"))
	}
	return val, nil
}

// New returns a new ACME API router.
func New(acmeAuth acme.Interface) api.RouterHandler {
	return &Handler{acmeAuth}
}

// Handler is the ACME request handler.
type Handler struct {
	Auth acme.Interface
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	getLink := h.Auth.GetLinkExplicit
	// Standard ACME API
	r.MethodFunc("GET", getLink(acme.NewNonceLink, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetNonce))))
	r.MethodFunc("HEAD", getLink(acme.NewNonceLink, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetNonce))))
	r.MethodFunc("GET", getLink(acme.DirectoryLink, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetDirectory))))
	r.MethodFunc("HEAD", getLink(acme.DirectoryLink, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetDirectory))))

	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.extractJWK(h.verifyAndExtractJWSPayload(next)))))))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.lookupJWK(h.verifyAndExtractJWSPayload(next)))))))))
	}

	r.MethodFunc("POST", getLink(acme.NewAccountLink, "{provisionerID}", false, nil), extractPayloadByJWK(h.NewAccount))
	r.MethodFunc("POST", getLink(acme.AccountLink, "{provisionerID}", false, nil, "{accID}"), extractPayloadByKid(h.GetUpdateAccount))
	r.MethodFunc("POST", getLink(acme.NewOrderLink, "{provisionerID}", false, nil), extractPayloadByKid(h.NewOrder))
	r.MethodFunc("POST", getLink(acme.OrderLink, "{provisionerID}", false, nil, "{ordID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrder)))
	r.MethodFunc("POST", getLink(acme.OrdersByAccountLink, "{provisionerID}", false, nil, "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrdersByAccount)))
	r.MethodFunc("POST", getLink(acme.FinalizeLink, "{provisionerID}", false, nil, "{ordID}"), extractPayloadByKid(h.FinalizeOrder))
	r.MethodFunc("POST", getLink(acme.AuthzLink, "{provisionerID}", false, nil, "{authzID}"), extractPayloadByKid(h.isPostAsGet(h.GetAuthz)))
	r.MethodFunc("POST", getLink(acme.ChallengeLink, "{provisionerID}", false, nil, "{chID}"), extractPayloadByKid(h.GetChallenge))
	r.MethodFunc("POST", getLink(acme.CertificateLink, "{provisionerID}", false, nil, "{certID}"), extractPayloadByKid(h.isPostAsGet(h.GetCertificate)))
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

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func (h *Handler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	dir, err := h.Auth.GetDirectory(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, dir)
}

// GetAuthz ACME api for retrieving an Authz.
func (h *Handler) GetAuthz(w http.ResponseWriter, r *http.Request) {
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	authz, err := h.Auth.GetAuthz(r.Context(), acc.GetID(), chi.URLParam(r, "authzID"))
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(r.Context(), acme.AuthzLink, true, authz.GetID()))
	api.JSON(w, authz)
}

// GetChallenge is the ACME api for retrieving a Challenge resource.
//
// Potential Challenges are requested by the client when creating an order.
// Once the client knows the appropriate validation resources are provisioned,
// it makes a POST-as-GET request to this endpoint in order to initiate the
// validation flow.
//
// The validation state machine describes the flow for a challenge.
//
//   https://tools.ietf.org/html/rfc8555#section-7.1.6
//
// Once a validation attempt has completed without error, the challenge's
// status is updated depending on the result (valid|invalid) of the server's
// validation attempt. Once this is the case, a challenge cannot be reset.
//
// If a challenge cannot be completed because no suitable data can be
// acquired the server (whilst communicating retry information) and the
// client (whilst respecting the information from the server) may request
// retries of the validation.
//
//   https://tools.ietf.org/html/rfc8555#section-8.2
//
// Retry status is communicated using the error field and by sending a
// Retry-After header back to the client.
//
// The request body is challenge-specific. The current challenges (http-01,
// dns-01, tls-alpn-01) simply expect an empty object ("{}") in the payload
// of the JWT sent by the client. We don't gain anything by stricly enforcing
// nonexistence of unknown attributes, or, in these three cases, enforcing
// an empty payload. And the spec also says to just ignore it:
//
// > The server MUST ignore any fields in the response object
// > that are not specified as response fields for this type of challenge.
//
//    https://tools.ietf.org/html/rfc8555#section-7.5.1
//
func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// Just verify that the payload was set since the client is required
	// to send _something_.
	_, err = payloadFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	var (
		ch   *acme.Challenge
		chID = chi.URLParam(r, "chID")
	)
	ch, err = h.Auth.ValidateChallenge(r.Context(), acc.GetID(), chID, acc.GetKey())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Add("Link", link(h.Auth.GetLink(r.Context(), acme.AuthzLink, true, ch.GetAuthzID()), "up"))
	w.Header().Set("Location", h.Auth.GetLink(r.Context(), acme.ChallengeLink, true, ch.GetID()))

	if ch.Status == acme.StatusProcessing {
		w.Header().Add("Retry-After", ch.RetryAfter)
		// 200s are cachable. Don't cache this because it will likely change.
		w.Header().Add("Cache-Control", "no-cache")
	}

	api.JSON(w, ch)
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	certID := chi.URLParam(r, "certID")
	certBytes, err := h.Auth.GetCertificate(acc.GetID(), certID)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.Write(certBytes)
}
