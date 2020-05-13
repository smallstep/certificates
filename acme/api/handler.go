package api

import (
	"fmt"
	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/jose"
	"net/http"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, typ)
}

type contextKey string

const (
	accContextKey         = contextKey("acc")
	jwsContextKey         = contextKey("jws")
	jwkContextKey         = contextKey("jwk")
	payloadContextKey     = contextKey("payload")
	provisionerContextKey = contextKey("provisioner")
)

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

func accountFromContext(r *http.Request) (*acme.Account, error) {
	val, ok := r.Context().Value(accContextKey).(*acme.Account)
	if !ok || val == nil {
		return nil, acme.AccountDoesNotExistErr(nil)
	}
	return val, nil
}
func jwkFromContext(r *http.Request) (*jose.JSONWebKey, error) {
	val, ok := r.Context().Value(jwkContextKey).(*jose.JSONWebKey)
	if !ok || val == nil {
		return nil, acme.ServerInternalErr(errors.Errorf("jwk expected in request context"))
	}
	return val, nil
}
func jwsFromContext(r *http.Request) (*jose.JSONWebSignature, error) {
	val, ok := r.Context().Value(jwsContextKey).(*jose.JSONWebSignature)
	if !ok || val == nil {
		return nil, acme.ServerInternalErr(errors.Errorf("jws expected in request context"))
	}
	return val, nil
}
func payloadFromContext(r *http.Request) (*payloadInfo, error) {
	val, ok := r.Context().Value(payloadContextKey).(*payloadInfo)
	if !ok || val == nil {
		return nil, acme.ServerInternalErr(errors.Errorf("payload expected in request context"))
	}
	return val, nil
}
func provisionerFromContext(r *http.Request) (provisioner.Interface, error) {
	val, ok := r.Context().Value(provisionerContextKey).(provisioner.Interface)
	if !ok || val == nil {
		return nil, acme.ServerInternalErr(errors.Errorf("provisioner expected in request context"))
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
	getLink := h.Auth.GetLink
	// Standard ACME API
	r.MethodFunc("GET", getLink(acme.NewNonceLink, "{provisionerID}", false), h.lookupProvisioner(h.addNonce(h.GetNonce)))
	r.MethodFunc("HEAD", getLink(acme.NewNonceLink, "{provisionerID}", false), h.lookupProvisioner(h.addNonce(h.GetNonce)))
	r.MethodFunc("GET", getLink(acme.DirectoryLink, "{provisionerID}", false), h.lookupProvisioner(h.addNonce(h.GetDirectory)))
	r.MethodFunc("HEAD", getLink(acme.DirectoryLink, "{provisionerID}", false), h.lookupProvisioner(h.addNonce(h.GetDirectory)))

	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.extractJWK(h.verifyAndExtractJWSPayload(next))))))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.lookupJWK(h.verifyAndExtractJWSPayload(next))))))))
	}

	r.MethodFunc("POST", getLink(acme.NewAccountLink, "{provisionerID}", false), extractPayloadByJWK(h.NewAccount))
	r.MethodFunc("POST", getLink(acme.AccountLink, "{provisionerID}", false, "{accID}"), extractPayloadByKid(h.GetUpdateAccount))
	r.MethodFunc("POST", getLink(acme.NewOrderLink, "{provisionerID}", false), extractPayloadByKid(h.NewOrder))
	r.MethodFunc("POST", getLink(acme.OrderLink, "{provisionerID}", false, "{ordID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrder)))
	r.MethodFunc("POST", getLink(acme.OrdersByAccountLink, "{provisionerID}", false, "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrdersByAccount)))
	r.MethodFunc("POST", getLink(acme.FinalizeLink, "{provisionerID}", false, "{ordID}"), extractPayloadByKid(h.FinalizeOrder))
	r.MethodFunc("POST", getLink(acme.AuthzLink, "{provisionerID}", false, "{authzID}"), extractPayloadByKid(h.isPostAsGet(h.GetAuthz)))
	r.MethodFunc("POST", getLink(acme.ChallengeLink, "{provisionerID}", false, "{chID}"), extractPayloadByKid(h.GetChallenge))
	r.MethodFunc("POST", getLink(acme.CertificateLink, "{provisionerID}", false, "{certID}"), extractPayloadByKid(h.isPostAsGet(h.GetCertificate)))
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
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	dir := h.Auth.GetDirectory(prov)
	api.JSON(w, dir)
}

// GetAuthz ACME api for retrieving an Authz.
func (h *Handler) GetAuthz(w http.ResponseWriter, r *http.Request) {
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	acc, err := accountFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	authz, err := h.Auth.GetAuthz(prov, acc.GetID(), chi.URLParam(r, "authzID"))
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.AuthzLink, acme.URLSafeProvisionerName(prov), true, authz.GetID()))
	api.JSON(w, authz)
}

// ACME api for retrieving the Challenge resource.
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
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	acc, err := accountFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// Just verify that the payload was set since the client is required
	// to send _something_.
	_, err = payloadFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	var (
		ch   *acme.Challenge
		chID = chi.URLParam(r, "chID")
	)
	ch, err = h.Auth.ValidateChallenge(prov, acc.GetID(), chID, acc.GetKey())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	switch ch.Status {
	case acme.StatusPending:
		panic("validation attempt did not move challenge to the processing state")
	// When a transient error occurs, the challenge will not be progressed to the `invalid` state.
	// Add a Retry-After header to indicate that the client should check again in the future.
	case acme.StatusProcessing:
		w.Header().Add("Retry-After", ch.RetryAfter)
		w.Header().Add("Cache-Control", "no-cache")
		api.JSON(w, ch)
	case acme.StatusValid, acme.StatusInvalid:
		getLink := h.Auth.GetLink
		w.Header().Add("Link", link(getLink(acme.AuthzLink, acme.URLSafeProvisionerName(prov), true, ch.GetAuthzID()), "up"))
		w.Header().Set("Location", getLink(acme.ChallengeLink, acme.URLSafeProvisionerName(prov), true, ch.GetID()))
		api.JSON(w, ch)
	default:
		panic("unexpected challenge state" + ch.Status)
	}
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	acc, err := accountFromContext(r)
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
