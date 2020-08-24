package api

import (
	"context"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

func logNonce(w http.ResponseWriter, nonce string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"nonce": nonce,
		}
		rl.WithFields(m)
	}
}

// baseURLFromRequest determines the base URL which should be used for
// constructing link URLs in e.g. the ACME directory result by taking the
// request Host into consideration.
//
// If the Request.Host is an empty string, we return an empty string, to
// indicate that the configured URL values should be used instead.  If this
// function returns a non-empty result, then this should be used in
// constructing ACME link URLs.
func baseURLFromRequest(r *http.Request) *url.URL {
	// NOTE: See https://github.com/letsencrypt/boulder/blob/master/web/relative.go
	// for an implementation that allows HTTP requests using the x-forwarded-proto
	// header.

	if r.Host == "" {
		return nil
	}
	return &url.URL{Scheme: "https", Host: r.Host}
}

// baseURLFromRequest is a middleware that extracts and caches the baseURL
// from the request.
// E.g. https://ca.smallstep.com/
func (h *Handler) baseURLFromRequest(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), acme.BaseURLContextKey, baseURLFromRequest(r))
		next(w, r.WithContext(ctx))
	}
}

// addNonce is a middleware that adds a nonce to the response header.
func (h *Handler) addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := h.Auth.NewNonce()
		if err != nil {
			api.WriteError(w, err)
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Cache-Control", "no-store")
		logNonce(w, nonce)
		next(w, r)
	}
}

// addDirLink is a middleware that adds a 'Link' response reader with the
// directory index url.
func (h *Handler) addDirLink(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", link(h.Auth.GetLink(r.Context(),
			acme.DirectoryLink, true), "index"))
		next(w, r)
	}
}

// verifyContentType is a middleware that verifies that content type is
// application/jose+json.
func (h *Handler) verifyContentType(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		var expected []string
		if strings.Contains(r.URL.Path, h.Auth.GetLink(r.Context(), acme.CertificateLink, false, "")) {
			// GET /certificate requests allow a greater range of content types.
			expected = []string{"application/jose+json", "application/pkix-cert", "application/pkcs7-mime"}
		} else {
			// By default every request should have content-type applictaion/jose+json.
			expected = []string{"application/jose+json"}
		}
		for _, e := range expected {
			if ct == e {
				next(w, r)
				return
			}
		}
		api.WriteError(w, acme.MalformedErr(errors.Errorf(
			"expected content-type to be in %s, but got %s", expected, ct)))
	}
}

// parseJWS is a middleware that parses a request body into a JSONWebSignature struct.
func (h *Handler) parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Wrap(err, "failed to read request body")))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to parse JWS from request body")))
			return
		}
		ctx := context.WithValue(r.Context(), acme.JwsContextKey, jws)
		next(w, r.WithContext(ctx))
	}
}

// validateJWS checks the request body for to verify that it meets ACME
// requirements for a JWS.
//
// The JWS MUST NOT have multiple signatures
// The JWS Unencoded Payload Option [RFC7797] MUST NOT be used
// The JWS Unprotected Header [RFC7515] MUST NOT be used
// The JWS Payload MUST NOT be detached
// The JWS Protected Header MUST include the following fields:
//   * “alg” (Algorithm)
//     * This field MUST NOT contain “none” or a Message Authentication Code
//       (MAC) algorithm (e.g. one in which the algorithm registry description
//       mentions MAC/HMAC).
//   * “nonce” (defined in Section 6.5)
//   * “url” (defined in Section 6.4)
//   * Either “jwk” (JSON Web Key) or “kid” (Key ID) as specified below<Paste>
func (h *Handler) validateJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, err := acme.JwsFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if len(jws.Signatures) == 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("request body does not contain a signature")))
			return
		}
		if len(jws.Signatures) > 1 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("request body contains more than one signature")))
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if len(uh.KeyID) > 0 ||
			uh.JSONWebKey != nil ||
			len(uh.Algorithm) > 0 ||
			len(uh.Nonce) > 0 ||
			len(uh.ExtraHeaders) > 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("unprotected header must not be used")))
			return
		}
		hdr := sig.Protected
		switch hdr.Algorithm {
		case jose.RS256, jose.RS384, jose.RS512:
			if hdr.JSONWebKey != nil {
				switch k := hdr.JSONWebKey.Key.(type) {
				case *rsa.PublicKey:
					if k.Size() < keyutil.MinRSAKeyBytes {
						api.WriteError(w, acme.MalformedErr(errors.Errorf("rsa "+
							"keys must be at least %d bits (%d bytes) in size",
							8*keyutil.MinRSAKeyBytes, keyutil.MinRSAKeyBytes)))
						return
					}
				default:
					api.WriteError(w, acme.MalformedErr(errors.Errorf("jws key type and algorithm do not match")))
					return
				}
			}
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
			// we good
		default:
			api.WriteError(w, acme.MalformedErr(errors.Errorf("unsuitable algorithm: %s", hdr.Algorithm)))
			return
		}

		// Check the validity/freshness of the Nonce.
		if err := h.Auth.UseNonce(hdr.Nonce); err != nil {
			api.WriteError(w, err)
			return
		}

		// Check that the JWS url matches the requested url.
		jwsURL, ok := hdr.ExtraHeaders["url"].(string)
		if !ok {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("jws missing url protected header")))
			return
		}
		reqURL := &url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path}
		if jwsURL != reqURL.String() {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL)))
			return
		}

		if hdr.JSONWebKey != nil && len(hdr.KeyID) > 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("jwk and kid are mutually exclusive")))
			return
		}
		if hdr.JSONWebKey == nil && len(hdr.KeyID) == 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("either jwk or kid must be defined in jws protected header")))
			return
		}
		next(w, r)
	}
}

// extractJWK is a middleware that extracts the JWK from the JWS and saves it
// in the context. Make sure to parse and validate the JWS before running this
// middleware.
func (h *Handler) extractJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, err := acme.JwsFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("jwk expected in protected header")))
			return
		}
		if !jwk.Valid() {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("invalid jwk in protected header")))
			return
		}
		ctx = context.WithValue(ctx, acme.JwkContextKey, jwk)
		acc, err := h.Auth.GetAccountByKey(ctx, jwk)
		switch {
		case nosql.IsErrNotFound(err):
			// For NewAccount requests ...
			break
		case err != nil:
			api.WriteError(w, err)
			return
		default:
			if !acc.IsValid() {
				api.WriteError(w, acme.UnauthorizedErr(errors.New("account is not active")))
				return
			}
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
		}
		next(w, r.WithContext(ctx))
	}
}

// lookupProvisioner loads the provisioner associated with the request.
// Responsds 404 if the provisioner does not exist.
func (h *Handler) lookupProvisioner(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		name := chi.URLParam(r, "provisionerID")
		provID, err := url.PathUnescape(name)
		if err != nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Wrapf(err, "error url unescaping provisioner id '%s'", name)))
			return
		}
		p, err := h.Auth.LoadProvisionerByID("acme/" + provID)
		if err != nil {
			api.WriteError(w, err)
			return
		}
		acmeProv, ok := p.(*provisioner.ACME)
		if !ok {
			api.WriteError(w, acme.AccountDoesNotExistErr(errors.New("provisioner must be of type ACME")))
			return
		}
		ctx = context.WithValue(ctx, acme.ProvisionerContextKey, acme.Provisioner(acmeProv))
		next(w, r.WithContext(ctx))
	}
}

// lookupJWK loads the JWK associated with the acme account referenced by the
// kid parameter of the signed payload.
// Make sure to parse and validate the JWS before running this middleware.
func (h *Handler) lookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, err := acme.JwsFromContext(ctx)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		kidPrefix := h.Auth.GetLink(ctx, acme.AccountLink, true, "")
		kid := jws.Signatures[0].Protected.KeyID
		if !strings.HasPrefix(kid, kidPrefix) {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("kid does not have "+
				"required prefix; expected %s, but got %s", kidPrefix, kid)))
			return
		}

		accID := strings.TrimPrefix(kid, kidPrefix)
		acc, err := h.Auth.GetAccount(r.Context(), accID)
		switch {
		case nosql.IsErrNotFound(err):
			api.WriteError(w, acme.AccountDoesNotExistErr(nil))
			return
		case err != nil:
			api.WriteError(w, err)
			return
		default:
			if !acc.IsValid() {
				api.WriteError(w, acme.UnauthorizedErr(errors.New("account is not active")))
				return
			}
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, acme.JwkContextKey, acc.Key)
			next(w, r.WithContext(ctx))
			return
		}
	}
}

// verifyAndExtractJWSPayload extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func (h *Handler) verifyAndExtractJWSPayload(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, err := acme.JwsFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}
		jwk, err := acme.JwkFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if len(jwk.Algorithm) != 0 && jwk.Algorithm != jws.Signatures[0].Protected.Algorithm {
			api.WriteError(w, acme.MalformedErr(errors.New("verifier and signature algorithm do not match")))
			return
		}
		payload, err := jws.Verify(jwk)
		if err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "error verifying jws")))
			return
		}
		ctx := context.WithValue(r.Context(), acme.PayloadContextKey, &payloadInfo{
			value:       payload,
			isPostAsGet: string(payload) == "",
			isEmptyJSON: string(payload) == "{}",
		})
		next(w, r.WithContext(ctx))
	}
}

// isPostAsGet asserts that the request is a PostAsGet (empty JWS payload).
func (h *Handler) isPostAsGet(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := payloadFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if !payload.isPostAsGet {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("expected POST-as-GET")))
			return
		}
		next(w, r)
	}
}
