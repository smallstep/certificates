package api

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/nosql"
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

// addNonce is a middleware that adds a nonce to the response header.
func addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		db := acme.MustDatabaseFromContext(r.Context())
		nonce, err := db.CreateNonce(r.Context())
		if err != nil {
			render.Error(w, err)
			return
		}
		w.Header().Set("Replay-Nonce", string(nonce))
		w.Header().Set("Cache-Control", "no-store")
		logNonce(w, string(nonce))
		next(w, r)
	}
}

// addDirLink is a middleware that adds a 'Link' response reader with the
// directory index url.
func addDirLink(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		linker := acme.MustLinkerFromContext(ctx)

		w.Header().Add("Link", link(linker.GetLink(ctx, acme.DirectoryLinkType), "index"))
		next(w, r)
	}
}

// verifyContentType is a middleware that verifies that content type is
// application/jose+json.
func verifyContentType(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := provisionerFromContext(r.Context())
		if err != nil {
			render.Error(w, err)
			return
		}

		u := &url.URL{
			Path: acme.GetUnescapedPathSuffix(acme.CertificateLinkType, p.GetName(), ""),
		}

		var expected []string
		if strings.Contains(r.URL.String(), u.EscapedPath()) {
			// GET /certificate requests allow a greater range of content types.
			expected = []string{"application/jose+json", "application/pkix-cert", "application/pkcs7-mime"}
		} else {
			// By default every request should have content-type applictaion/jose+json.
			expected = []string{"application/jose+json"}
		}

		ct := r.Header.Get("Content-Type")
		for _, e := range expected {
			if ct == e {
				next(w, r)
				return
			}
		}
		render.Error(w, acme.NewError(acme.ErrorMalformedType,
			"expected content-type to be in %s, but got %s", expected, ct))
	}
}

// parseJWS is a middleware that parses a request body into a JSONWebSignature struct.
func parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Error(w, acme.WrapErrorISE(err, "failed to read request body"))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			render.Error(w, acme.WrapError(acme.ErrorMalformedType, err, "failed to parse JWS from request body"))
			return
		}
		ctx := context.WithValue(r.Context(), jwsContextKey, jws)
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
//   - “alg” (Algorithm).
//     This field MUST NOT contain “none” or a Message Authentication Code
//     (MAC) algorithm (e.g. one in which the algorithm registry description
//     mentions MAC/HMAC).
//   - “nonce” (defined in Section 6.5)
//   - “url” (defined in Section 6.4)
//   - Either “jwk” (JSON Web Key) or “kid” (Key ID) as specified below<Paste>
func validateJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := acme.MustDatabaseFromContext(ctx)

		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}
		if len(jws.Signatures) == 0 {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "request body does not contain a signature"))
			return
		}
		if len(jws.Signatures) > 1 {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "request body contains more than one signature"))
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if len(uh.KeyID) > 0 ||
			uh.JSONWebKey != nil ||
			len(uh.Algorithm) > 0 ||
			len(uh.Nonce) > 0 ||
			len(uh.ExtraHeaders) > 0 {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "unprotected header must not be used"))
			return
		}
		hdr := sig.Protected
		switch hdr.Algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			if hdr.JSONWebKey != nil {
				switch k := hdr.JSONWebKey.Key.(type) {
				case *rsa.PublicKey:
					if k.Size() < keyutil.MinRSAKeyBytes {
						render.Error(w, acme.NewError(acme.ErrorMalformedType,
							"rsa keys must be at least %d bits (%d bytes) in size",
							8*keyutil.MinRSAKeyBytes, keyutil.MinRSAKeyBytes))
						return
					}
				default:
					render.Error(w, acme.NewError(acme.ErrorMalformedType,
						"jws key type and algorithm do not match"))
					return
				}
			}
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
			// we good
		default:
			render.Error(w, acme.NewError(acme.ErrorBadSignatureAlgorithmType, "unsuitable algorithm: %s", hdr.Algorithm))
			return
		}

		// Check the validity/freshness of the Nonce.
		if err := db.DeleteNonce(ctx, acme.Nonce(hdr.Nonce)); err != nil {
			render.Error(w, err)
			return
		}

		// Check that the JWS url matches the requested url.
		jwsURL, ok := hdr.ExtraHeaders["url"].(string)
		if !ok {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "jws missing url protected header"))
			return
		}
		reqURL := &url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path}
		if jwsURL != reqURL.String() {
			render.Error(w, acme.NewError(acme.ErrorMalformedType,
				"url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL))
			return
		}

		if hdr.JSONWebKey != nil && len(hdr.KeyID) > 0 {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "jwk and kid are mutually exclusive"))
			return
		}
		if hdr.JSONWebKey == nil && hdr.KeyID == "" {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "either jwk or kid must be defined in jws protected header"))
			return
		}
		next(w, r)
	}
}

// extractJWK is a middleware that extracts the JWK from the JWS and saves it
// in the context. Make sure to parse and validate the JWS before running this
// middleware.
func extractJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := acme.MustDatabaseFromContext(ctx)

		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "jwk expected in protected header"))
			return
		}
		if !jwk.Valid() {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "invalid jwk in protected header"))
			return
		}

		// Overwrite KeyID with the JWK thumbprint.
		jwk.KeyID, err = acme.KeyToID(jwk)
		if err != nil {
			render.Error(w, acme.WrapErrorISE(err, "error getting KeyID from JWK"))
			return
		}

		// Store the JWK in the context.
		ctx = context.WithValue(ctx, jwkContextKey, jwk)

		// Get Account OR continue to generate a new one OR continue Revoke with certificate private key
		acc, err := db.GetAccountByKeyID(ctx, jwk.KeyID)
		switch {
		case errors.Is(err, acme.ErrNotFound):
			// For NewAccount and Revoke requests ...
			break
		case err != nil:
			render.Error(w, err)
			return
		default:
			if !acc.IsValid() {
				render.Error(w, acme.NewError(acme.ErrorUnauthorizedType, "account is not active"))
				return
			}
			ctx = context.WithValue(ctx, accContextKey, acc)
		}
		next(w, r.WithContext(ctx))
	}
}

// checkPrerequisites checks if all prerequisites for serving ACME
// are met by the CA configuration.
func checkPrerequisites(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// If the function is not set assume that all prerequisites are met.
		checkFunc, ok := acme.PrerequisitesCheckerFromContext(ctx)
		if ok {
			ok, err := checkFunc(ctx)
			if err != nil {
				render.Error(w, acme.WrapErrorISE(err, "error checking acme provisioner prerequisites"))
				return
			}
			if !ok {
				render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "acme provisioner configuration lacks prerequisites"))
				return
			}
		}
		next(w, r)
	}
}

// lookupJWK loads the JWK associated with the acme account referenced by the
// kid parameter of the signed payload.
// Make sure to parse and validate the JWS before running this middleware.
func lookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := acme.MustDatabaseFromContext(ctx)
		linker := acme.MustLinkerFromContext(ctx)

		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}

		kidPrefix := linker.GetLink(ctx, acme.AccountLinkType, "")
		kid := jws.Signatures[0].Protected.KeyID
		if !strings.HasPrefix(kid, kidPrefix) {
			render.Error(w, acme.NewError(acme.ErrorMalformedType,
				"kid does not have required prefix; expected %s, but got %s",
				kidPrefix, kid))
			return
		}

		accID := strings.TrimPrefix(kid, kidPrefix)
		acc, err := db.GetAccount(ctx, accID)
		switch {
		case nosql.IsErrNotFound(err):
			render.Error(w, acme.NewError(acme.ErrorAccountDoesNotExistType, "account with ID '%s' not found", accID))
			return
		case err != nil:
			render.Error(w, err)
			return
		default:
			if !acc.IsValid() {
				render.Error(w, acme.NewError(acme.ErrorUnauthorizedType, "account is not active"))
				return
			}
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, jwkContextKey, acc.Key)
			next(w, r.WithContext(ctx))
			return
		}
	}
}

// extractOrLookupJWK forwards handling to either extractJWK or
// lookupJWK based on the presence of a JWK or a KID, respectively.
func extractOrLookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}

		// at this point the JWS has already been verified (if correctly configured in middleware),
		// and it can be used to check if a JWK exists. This flow is used when the ACME client
		// signed the payload with a certificate private key.
		if canExtractJWKFrom(jws) {
			extractJWK(next)(w, r)
			return
		}

		// default to looking up the JWK based on KeyID. This flow is used when the ACME client
		// signed the payload with an account private key.
		lookupJWK(next)(w, r)
	}
}

// canExtractJWKFrom checks if the JWS has a JWK that can be extracted
func canExtractJWKFrom(jws *jose.JSONWebSignature) bool {
	if jws == nil {
		return false
	}
	if len(jws.Signatures) == 0 {
		return false
	}
	return jws.Signatures[0].Protected.JSONWebKey != nil
}

// verifyAndExtractJWSPayload extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func verifyAndExtractJWSPayload(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}
		jwk, err := jwkFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}
		if jwk.Algorithm != "" && jwk.Algorithm != jws.Signatures[0].Protected.Algorithm {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "verifier and signature algorithm do not match"))
			return
		}
		payload, err := jws.Verify(jwk)
		if err != nil {
			render.Error(w, acme.WrapError(acme.ErrorMalformedType, err, "error verifying jws"))
			return
		}
		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{
			value:       payload,
			isPostAsGet: len(payload) == 0,
			isEmptyJSON: string(payload) == "{}",
		})
		next(w, r.WithContext(ctx))
	}
}

// isPostAsGet asserts that the request is a PostAsGet (empty JWS payload).
func isPostAsGet(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := payloadFromContext(r.Context())
		if err != nil {
			render.Error(w, err)
			return
		}
		if !payload.isPostAsGet {
			render.Error(w, acme.NewError(acme.ErrorMalformedType, "expected POST-as-GET"))
			return
		}
		next(w, r)
	}
}

// ContextKey is the key type for storing and searching for ACME request
// essentials in the context of a request.
type ContextKey string

const (
	// accContextKey account key
	accContextKey = ContextKey("acc")
	// jwsContextKey jws key
	jwsContextKey = ContextKey("jws")
	// jwkContextKey jwk key
	jwkContextKey = ContextKey("jwk")
	// payloadContextKey payload key
	payloadContextKey = ContextKey("payload")
)

// accountFromContext searches the context for an ACME account. Returns the
// account or an error.
func accountFromContext(ctx context.Context) (*acme.Account, error) {
	val, ok := ctx.Value(accContextKey).(*acme.Account)
	if !ok || val == nil {
		return nil, acme.NewError(acme.ErrorAccountDoesNotExistType, "account not in context")
	}
	return val, nil
}

// jwkFromContext searches the context for a JWK. Returns the JWK or an error.
func jwkFromContext(ctx context.Context) (*jose.JSONWebKey, error) {
	val, ok := ctx.Value(jwkContextKey).(*jose.JSONWebKey)
	if !ok || val == nil {
		return nil, acme.NewErrorISE("jwk expected in request context")
	}
	return val, nil
}

// jwsFromContext searches the context for a JWS. Returns the JWS or an error.
func jwsFromContext(ctx context.Context) (*jose.JSONWebSignature, error) {
	val, ok := ctx.Value(jwsContextKey).(*jose.JSONWebSignature)
	if !ok || val == nil {
		return nil, acme.NewErrorISE("jws expected in request context")
	}
	return val, nil
}

// provisionerFromContext searches the context for a provisioner. Returns the
// provisioner or an error.
func provisionerFromContext(ctx context.Context) (acme.Provisioner, error) {
	p, ok := acme.ProvisionerFromContext(ctx)
	if !ok || p == nil {
		return nil, acme.NewErrorISE("provisioner expected in request context")
	}
	return p, nil
}

// acmeProvisionerFromContext searches the context for an ACME provisioner. Returns
// pointer to an ACME provisioner or an error.
func acmeProvisionerFromContext(ctx context.Context) (*provisioner.ACME, error) {
	p, err := provisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ap, ok := p.(*provisioner.ACME)
	if !ok {
		return nil, acme.NewErrorISE("provisioner in context is not an ACME provisioner")
	}

	return ap, nil
}

// payloadFromContext searches the context for a payload. Returns the payload
// or an error.
func payloadFromContext(ctx context.Context) (*payloadInfo, error) {
	val, ok := ctx.Value(payloadContextKey).(*payloadInfo)
	if !ok || val == nil {
		return nil, acme.NewErrorISE("payload expected in request context")
	}
	return val, nil
}
