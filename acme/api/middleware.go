package api

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
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
			render.Error(w, r, err)
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
			render.Error(w, r, err)
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
		render.Error(w, r, acme.NewError(acme.ErrorMalformedType,
			"expected content-type to be in %s, but got %s", expected, ct))
	}
}

// parseJWS is a middleware that parses a request body into a JSONWebSignature struct.
func parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Error(w, r, acme.WrapErrorISE(err, "failed to read request body"))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err, "failed to parse JWS from request body"))
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
			render.Error(w, r, err)
			return
		}
		if len(jws.Signatures) == 0 {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "request body does not contain a signature"))
			return
		}
		if len(jws.Signatures) > 1 {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "request body contains more than one signature"))
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if uh.KeyID != "" ||
			uh.JSONWebKey != nil ||
			uh.Algorithm != "" ||
			uh.Nonce != "" ||
			len(uh.ExtraHeaders) > 0 {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "unprotected header must not be used"))
			return
		}
		hdr := sig.Protected
		switch hdr.Algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			if hdr.JSONWebKey != nil {
				switch k := hdr.JSONWebKey.Key.(type) {
				case *rsa.PublicKey:
					if k.Size() < keyutil.MinRSAKeyBytes {
						render.Error(w, r, acme.NewError(acme.ErrorMalformedType,
							"rsa keys must be at least %d bits (%d bytes) in size",
							8*keyutil.MinRSAKeyBytes, keyutil.MinRSAKeyBytes))
						return
					}
				default:
					render.Error(w, r, acme.NewError(acme.ErrorMalformedType,
						"jws key type and algorithm do not match"))
					return
				}
			}
		case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
			// we good
		default:
			render.Error(w, r, acme.NewError(acme.ErrorBadSignatureAlgorithmType, "unsuitable algorithm: %s", hdr.Algorithm))
			return
		}

		// Check the validity/freshness of the Nonce.
		if err := db.DeleteNonce(ctx, acme.Nonce(hdr.Nonce)); err != nil {
			render.Error(w, r, err)
			return
		}

		// Check that the JWS url matches the requested url.
		jwsURL, ok := hdr.ExtraHeaders["url"].(string)
		if !ok {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "jws missing url protected header"))
			return
		}
		reqURL := &url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path}
		if jwsURL != reqURL.String() {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType,
				"url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL))
			return
		}

		if hdr.JSONWebKey != nil && hdr.KeyID != "" {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "jwk and kid are mutually exclusive"))
			return
		}
		if hdr.JSONWebKey == nil && hdr.KeyID == "" {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "either jwk or kid must be defined in jws protected header"))
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
			render.Error(w, r, err)
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "jwk expected in protected header"))
			return
		}
		if !jwk.Valid() {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "invalid jwk in protected header"))
			return
		}

		// Overwrite KeyID with the JWK thumbprint.
		jwk.KeyID, err = acme.KeyToID(jwk)
		if err != nil {
			render.Error(w, r, acme.WrapErrorISE(err, "error getting KeyID from JWK"))
			return
		}

		// Store the JWK in the context.
		ctx = context.WithValue(ctx, jwkContextKey, jwk)

		// Get Account OR continue to generate a new one OR continue Revoke with certificate private key
		acc, err := db.GetAccountByKeyID(ctx, jwk.KeyID)
		switch {
		case acme.IsErrNotFound(err):
			// For NewAccount and Revoke requests ...
			break
		case err != nil:
			render.Error(w, r, err)
			return
		default:
			if !acc.IsValid() {
				render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType, "account is not active"))
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
				render.Error(w, r, acme.WrapErrorISE(err, "error checking acme provisioner prerequisites"))
				return
			}
			if !ok {
				render.Error(w, r, acme.NewError(acme.ErrorNotImplementedType, "acme provisioner configuration lacks prerequisites"))
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

		jws, err := jwsFromContext(ctx)
		if err != nil {
			render.Error(w, r, err)
			return
		}

		kid := jws.Signatures[0].Protected.KeyID
		if kid == "" {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "signature missing 'kid'"))
			return
		}

		accID := path.Base(kid)
		acc, err := db.GetAccount(ctx, accID)
		switch {
		case acme.IsErrNotFound(err):
			render.Error(w, r, acme.NewError(acme.ErrorAccountDoesNotExistType, "account with ID '%s' not found", accID))
			return
		case err != nil:
			render.Error(w, r, err)
			return
		default:
			if !acc.IsValid() {
				render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType, "account is not active"))
				return
			}

			if storedLocation := acc.GetLocation(); storedLocation != "" {
				if kid != storedLocation {
					// ACME accounts should have a stored location equivalent to the
					// kid in the ACME request.
					render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
						"kid does not match stored account location; expected %s, but got %s",
						storedLocation, kid))
					return
				}

				// Verify that the provisioner with which the account was created
				// matches the provisioner in the request URL.
				reqProv := acme.MustProvisionerFromContext(ctx)
				switch {
				case acc.ProvisionerID == "" && acc.ProvisionerName != reqProv.GetName():
					render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
						"account provisioner does not match requested provisioner; account provisioner = %s, requested provisioner = %s",
						acc.ProvisionerName, reqProv.GetName()))
					return
				case acc.ProvisionerID != "" && acc.ProvisionerID != reqProv.GetID():
					render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
						"account provisioner does not match requested provisioner; account provisioner = %s, requested provisioner = %s",
						acc.ProvisionerID, reqProv.GetID()))
					return
				}
			} else {
				// This code will only execute for old ACME accounts that do
				// not have a cached location. The following validation was
				// the original implementation of the `kid` check which has
				// since been deprecated. However, the code will remain to
				// ensure consistent behavior for old ACME accounts.
				linker := acme.MustLinkerFromContext(ctx)
				kidPrefix := linker.GetLink(ctx, acme.AccountLinkType, "")
				if !strings.HasPrefix(kid, kidPrefix) {
					render.Error(w, r, acme.NewError(acme.ErrorMalformedType,
						"kid does not have required prefix; expected %s, but got %s",
						kidPrefix, kid))
					return
				}
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
			render.Error(w, r, err)
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
			render.Error(w, r, err)
			return
		}
		jwk, err := jwkFromContext(ctx)
		if err != nil {
			render.Error(w, r, err)
			return
		}
		if jwk.Algorithm != "" && jwk.Algorithm != jws.Signatures[0].Protected.Algorithm {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "verifier and signature algorithm do not match"))
			return
		}

		payload, err := jws.Verify(jwk)
		switch {
		case errors.Is(err, jose.ErrCryptoFailure):
			payload, err = retryVerificationWithPatchedSignatures(jws, jwk)
			if err != nil {
				render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err, "error verifying jws with patched signature(s)"))
				return
			}
		case err != nil:
			render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err, "error verifying jws"))
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

// retryVerificationWithPatchedSignatures retries verification of the JWS using
// the JWK by patching the JWS signatures if they're determined to be too short.
//
// Generally this shouldn't happen, but we've observed this to be the case with
// the macOS ACME client, which seems to omit (at least one) leading null
// byte(s). The error returned is `go-jose/go-jose: error in cryptographic
// primitive`, which is a sentinel error that hides the details of the actual
// underlying error, which is as follows: `go-jose/go-jose: invalid signature
// size, have 63 bytes, wanted 64`, for ES256.
func retryVerificationWithPatchedSignatures(jws *jose.JSONWebSignature, jwk *jose.JSONWebKey) (data []byte, err error) {
	originalSignatureValues := make([][]byte, len(jws.Signatures))
	patched := false
	defer func() {
		if patched && err != nil {
			for i, sig := range jws.Signatures {
				sig.Signature = originalSignatureValues[i]
				jws.Signatures[i] = sig
			}
		}
	}()
	for i, sig := range jws.Signatures {
		var expectedSize int
		alg := strings.ToUpper(sig.Header.Algorithm)
		switch alg {
		case jose.ES256:
			expectedSize = 64
		case jose.ES384:
			expectedSize = 96
		case jose.ES512:
			expectedSize = 132
		default:
			// other cases are (currently) ignored
			continue
		}

		switch diff := expectedSize - len(sig.Signature); diff {
		case 0:
			// expected length; nothing to do; will result in just doing the
			// same verification (as done before calling this function) again,
			// and thus an error will be returned.
			continue
		case 1:
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedR := make([]byte, expectedSize)
			copy(patchedR[1:], original) // [0x00, R.0:31, S.0:32], for expectedSize 64
			sig.Signature = patchedR
			jws.Signatures[i] = sig

			// verify it with a patched R; return early if successful; continue
			// with patching S if not.
			data, err = jws.Verify(jwk)
			if err == nil {
				return
			}

			patchedS := make([]byte, expectedSize)
			halfSize := expectedSize / 2
			copy(patchedS, original[:halfSize])              // [R.0:32], for expectedSize 64
			copy(patchedS[halfSize+1:], original[halfSize:]) // [R.0:32, 0x00, S.0:31]
			sig.Signature = patchedS
			jws.Signatures[i] = sig
		case 2:
			// assumption is currently the Apple case, in which only the
			// first null byte of R and/or S are removed, and thus not a case in
			// which two first bytes of either R or S are removed.
			patched = true
			original := make([]byte, expectedSize-diff)
			copy(original, sig.Signature)
			originalSignatureValues[i] = original

			patchedRS := make([]byte, expectedSize)
			halfSize := expectedSize / 2
			copy(patchedRS[1:], original[:halfSize-1])          // [0x00, R.0:31], for expectedSize 64
			copy(patchedRS[halfSize+1:], original[halfSize-1:]) // [0x00, R.0:31, 0x00, S.0:31]
			sig.Signature = patchedRS
			jws.Signatures[i] = sig
		default:
			// Technically, there can be multiple null bytes in either R or S,
			// so when the difference is larger than 2, there is more than one
			// option to pick. Apple's ACME client seems to only cut off the
			// first null byte of either R or S, so we don't do anything in this
			// case. Will result in just doing the same verification (as done
			// before calling this function) again, and thus an error will be
			// returned.
			// TODO(hs): log this specific case? It might mean some other ACME
			// client is doing weird things.
			continue
		}
	}

	data, err = jws.Verify(jwk)

	return
}

// isPostAsGet asserts that the request is a PostAsGet (empty JWS payload).
func isPostAsGet(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := payloadFromContext(r.Context())
		if err != nil {
			render.Error(w, r, err)
			return
		}
		if !payload.isPostAsGet {
			render.Error(w, r, acme.NewError(acme.ErrorMalformedType, "expected POST-as-GET"))
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
