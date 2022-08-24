package api

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql/database"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
)

var testBody = []byte("foo")

func testNext(w http.ResponseWriter, r *http.Request) {
	w.Write(testBody)
}

func newBaseContext(ctx context.Context, args ...interface{}) context.Context {
	for _, a := range args {
		switch v := a.(type) {
		case acme.DB:
			ctx = acme.NewDatabaseContext(ctx, v)
		case acme.Linker:
			ctx = acme.NewLinkerContext(ctx, v)
		case acme.PrerequisitesChecker:
			ctx = acme.NewPrerequisitesCheckerContext(ctx, v)
		}
	}
	return ctx
}

func TestHandler_addNonce(t *testing.T) {
	u := "https://ca.smallstep.com/acme/new-nonce"
	type test struct {
		db         acme.DB
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/AddNonce-error": func(t *testing.T) test {
			return test{
				db: &acme.MockDB{
					MockCreateNonce: func(ctx context.Context) (acme.Nonce, error) {
						return acme.Nonce(""), acme.NewErrorISE("force")
					},
				},
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &acme.MockDB{
					MockCreateNonce: func(ctx context.Context) (acme.Nonce, error) {
						return "bar", nil
					},
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := newBaseContext(context.Background(), tc.db)
			req := httptest.NewRequest("GET", u, nil).WithContext(ctx)
			w := httptest.NewRecorder()
			addNonce(testNext)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, res.Header["Replay-Nonce"], []string{"bar"})
				assert.Equals(t, res.Header["Cache-Control"], []string{"no-store"})
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_addDirLink(t *testing.T) {
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	type test struct {
		link       string
		statusCode int
		ctx        context.Context
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = acme.NewLinkerContext(ctx, acme.NewLinker("test.ca.smallstep.com", "acme"))
			return test{
				ctx:        ctx,
				link:       fmt.Sprintf("%s/acme/%s/directory", baseURL.String(), provName),
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/foo", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			addDirLink(testNext)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, res.Header["Link"], []string{fmt.Sprintf("<%s>;rel=\"index\"", tc.link)})
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_verifyContentType(t *testing.T) {
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	u := fmt.Sprintf("%s/acme/%s/certificate/abc123", baseURL.String(), escProvName)
	type test struct {
		ctx         context.Context
		contentType string
		err         *acme.Error
		statusCode  int
		url         string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/provisioner-not-set": func(t *testing.T) test {
			return test{
				url:         u,
				ctx:         context.Background(),
				contentType: "foo",
				statusCode:  500,
				err:         acme.NewErrorISE("provisioner expected in request context"),
			}
		},
		"fail/general-bad-content-type": func(t *testing.T) test {
			return test{
				url:         u,
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "foo",
				statusCode:  400,
				err:         acme.NewError(acme.ErrorMalformedType, "expected content-type to be in [application/jose+json], but got foo"),
			}
		},
		"fail/certificate-bad-content-type": func(t *testing.T) test {
			return test{
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "foo",
				statusCode:  400,
				err:         acme.NewError(acme.ErrorMalformedType, "expected content-type to be in [application/jose+json application/pkix-cert application/pkcs7-mime], but got foo"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "application/jose+json",
				statusCode:  200,
			}
		},
		"ok/certificate/pkix-cert": func(t *testing.T) test {
			return test{
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "application/pkix-cert",
				statusCode:  200,
			}
		},
		"ok/certificate/jose+json": func(t *testing.T) test {
			return test{
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "application/jose+json",
				statusCode:  200,
			}
		},
		"ok/certificate/pkcs7-mime": func(t *testing.T) test {
			return test{
				ctx:         acme.NewProvisionerContext(context.Background(), prov),
				contentType: "application/pkcs7-mime",
				statusCode:  200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			_u := u
			if tc.url != "" {
				_u = tc.url
			}
			req := httptest.NewRequest("GET", _u, nil)
			req = req.WithContext(tc.ctx)
			req.Header.Add("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			verifyContentType(testNext)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_isPostAsGet(t *testing.T) {
	u := "https://ca.smallstep.com/acme/new-account"
	type test struct {
		ctx        context.Context
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-payload": func(t *testing.T) test {
			return test{
				ctx:        context.Background(),
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), payloadContextKey, nil),
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/not-post-as-get": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), payloadContextKey, &payloadInfo{}),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "expected POST-as-GET"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), payloadContextKey, &payloadInfo{isPostAsGet: true}),
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			// h := &Handler{}
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			isPostAsGet(testNext)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("force")
}
func (errReader) Close() error {
	return nil
}

func TestHandler_parseJWS(t *testing.T) {
	u := "https://ca.smallstep.com/acme/new-account"
	type test struct {
		next       nextHTTP
		body       io.Reader
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/read-body-error": func(t *testing.T) test {
			return test{
				body:       errReader(0),
				statusCode: 500,
				err:        acme.NewErrorISE("failed to read request body: force"),
			}
		},
		"fail/parse-jws-error": func(t *testing.T) test {
			return test{
				body:       strings.NewReader("foo"),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "failed to parse JWS from request body: square/go-jose: compact JWS format must have three parts"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, new(jose.SignerOptions))
			assert.FatalError(t, err)
			signed, err := signer.Sign([]byte("baz"))
			assert.FatalError(t, err)
			expRaw, err := signed.CompactSerialize()
			assert.FatalError(t, err)

			return test{
				body: strings.NewReader(expRaw),
				next: func(w http.ResponseWriter, r *http.Request) {
					jws, err := jwsFromContext(r.Context())
					assert.FatalError(t, err)
					gotRaw, err := jws.CompactSerialize()
					assert.FatalError(t, err)
					assert.Equals(t, gotRaw, expRaw)
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			// h := &Handler{}
			req := httptest.NewRequest("GET", u, tc.body)
			w := httptest.NewRecorder()
			parseJWS(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_verifyAndExtractJWSPayload(t *testing.T) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	_pub := jwk.Public()
	pub := &_pub
	so := new(jose.SignerOptions)
	so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk.Key,
	}, so)
	assert.FatalError(t, err)
	jws, err := signer.Sign([]byte("baz"))
	assert.FatalError(t, err)
	raw, err := jws.CompactSerialize()
	assert.FatalError(t, err)
	parsedJWS, err := jose.ParseJWS(raw)
	assert.FatalError(t, err)
	u := "https://ca.smallstep.com/acme/account/1234"
	type test struct {
		ctx        context.Context
		next       func(http.ResponseWriter, *http.Request)
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-jws": func(t *testing.T) test {
			return test{
				ctx:        context.Background(),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jws": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), jwsContextKey, nil),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/no-jwk": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 500,
				err:        acme.NewErrorISE("jwk expected in request context"),
			}
		},
		"fail/nil-jwk": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, parsedJWS)
			return test{
				ctx:        context.WithValue(ctx, jwsContextKey, nil),
				statusCode: 500,
				err:        acme.NewErrorISE("jwk expected in request context"),
			}
		},
		"fail/verify-jws-failure": func(t *testing.T) test {
			_jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			_pub := _jwk.Public()
			ctx := context.WithValue(context.Background(), jwsContextKey, parsedJWS)
			ctx = context.WithValue(ctx, jwkContextKey, &_pub)
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "error verifying jws: square/go-jose: error in cryptographic primitive"),
			}
		},
		"fail/algorithm-mismatch": func(t *testing.T) test {
			_pub := *pub
			clone := &_pub
			clone.Algorithm = jose.HS256
			ctx := context.WithValue(context.Background(), jwsContextKey, parsedJWS)
			ctx = context.WithValue(ctx, jwkContextKey, clone)
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "verifier and signature algorithm do not match"),
			}
		},
		"ok": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, parsedJWS)
			ctx = context.WithValue(ctx, jwkContextKey, pub)
			return test{
				ctx:        ctx,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					p, err := payloadFromContext(r.Context())
					assert.FatalError(t, err)
					if assert.NotNil(t, p) {
						assert.Equals(t, p.value, []byte("baz"))
						assert.False(t, p.isPostAsGet)
						assert.False(t, p.isEmptyJSON)
					}
					w.Write(testBody)
				},
			}
		},
		"ok/empty-algorithm-in-jwk": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, parsedJWS)
			ctx = context.WithValue(ctx, jwkContextKey, pub)
			return test{
				ctx:        ctx,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					p, err := payloadFromContext(r.Context())
					assert.FatalError(t, err)
					if assert.NotNil(t, p) {
						assert.Equals(t, p.value, []byte("baz"))
						assert.False(t, p.isPostAsGet)
						assert.False(t, p.isEmptyJSON)
					}
					w.Write(testBody)
				},
			}
		},
		"ok/post-as-get": func(t *testing.T) test {
			_jws, err := signer.Sign([]byte(""))
			assert.FatalError(t, err)
			_raw, err := _jws.CompactSerialize()
			assert.FatalError(t, err)
			_parsed, err := jose.ParseJWS(_raw)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), jwsContextKey, _parsed)
			ctx = context.WithValue(ctx, jwkContextKey, pub)
			return test{
				ctx:        ctx,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					p, err := payloadFromContext(r.Context())
					assert.FatalError(t, err)
					if assert.NotNil(t, p) {
						assert.Equals(t, p.value, []byte{})
						assert.True(t, p.isPostAsGet)
						assert.False(t, p.isEmptyJSON)
					}
					w.Write(testBody)
				},
			}
		},
		"ok/empty-json": func(t *testing.T) test {
			_jws, err := signer.Sign([]byte("{}"))
			assert.FatalError(t, err)
			_raw, err := _jws.CompactSerialize()
			assert.FatalError(t, err)
			_parsed, err := jose.ParseJWS(_raw)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), jwsContextKey, _parsed)
			ctx = context.WithValue(ctx, jwkContextKey, pub)
			return test{
				ctx:        ctx,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					p, err := payloadFromContext(r.Context())
					assert.FatalError(t, err)
					if assert.NotNil(t, p) {
						assert.Equals(t, p.value, []byte("{}"))
						assert.False(t, p.isPostAsGet)
						assert.True(t, p.isEmptyJSON)
					}
					w.Write(testBody)
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			// h := &Handler{}
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			verifyAndExtractJWSPayload(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_lookupJWK(t *testing.T) {
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	u := fmt.Sprintf("%s/acme/%s/account/1234",
		baseURL, provName)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	accID := "account-id"
	prefix := fmt.Sprintf("%s/acme/%s/account/",
		baseURL, provName)
	so := new(jose.SignerOptions)
	so.WithHeader("kid", fmt.Sprintf("%s%s", prefix, accID))
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk.Key,
	}, so)
	assert.FatalError(t, err)
	jws, err := signer.Sign([]byte("baz"))
	assert.FatalError(t, err)
	raw, err := jws.CompactSerialize()
	assert.FatalError(t, err)
	parsedJWS, err := jose.ParseJWS(raw)
	assert.FatalError(t, err)
	type test struct {
		linker     acme.Linker
		db         acme.DB
		ctx        context.Context
		next       func(http.ResponseWriter, *http.Request)
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-jws": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				linker:     acme.NewLinker("test.ca.smallstep.com", "acme"),
				ctx:        acme.NewProvisionerContext(context.Background(), prov),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jws": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				linker:     acme.NewLinker("test.ca.smallstep.com", "acme"),
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/no-kid": func(t *testing.T) test {
			_signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, new(jose.SignerOptions))
			assert.FatalError(t, err)
			_jws, err := _signer.Sign([]byte("baz"))
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, _jws)
			return test{
				db:         &acme.MockDB{},
				linker:     acme.NewLinker("test.ca.smallstep.com", "acme"),
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "kid does not have required prefix; expected %s, but got ", prefix),
			}
		},
		"fail/bad-kid-prefix": func(t *testing.T) test {
			_so := new(jose.SignerOptions)
			_so.WithHeader("kid", "foo")
			_signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, _so)
			assert.FatalError(t, err)
			_jws, err := _signer.Sign([]byte("baz"))
			assert.FatalError(t, err)
			_raw, err := _jws.CompactSerialize()
			assert.FatalError(t, err)
			_parsed, err := jose.ParseJWS(_raw)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, _parsed)
			return test{
				db:         &acme.MockDB{},
				linker:     acme.NewLinker("test.ca.smallstep.com", "acme"),
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "kid does not have required prefix; expected %s, but got foo", prefix),
			}
		},
		"fail/account-not-found": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				linker: acme.NewLinker("test.ca.smallstep.com", "acme"),
				db: &acme.MockDB{
					MockGetAccount: func(ctx context.Context, accID string) (*acme.Account, error) {
						assert.Equals(t, accID, accID)
						return nil, database.ErrNotFound
					},
				},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/GetAccount-error": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				linker: acme.NewLinker("test.ca.smallstep.com", "acme"),
				db: &acme.MockDB{
					MockGetAccount: func(ctx context.Context, id string) (*acme.Account, error) {
						assert.Equals(t, id, accID)
						return nil, acme.NewErrorISE("force")
					},
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"fail/account-not-valid": func(t *testing.T) test {
			acc := &acme.Account{Status: "deactivated"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				linker: acme.NewLinker("test.ca.smallstep.com", "acme"),
				db: &acme.MockDB{
					MockGetAccount: func(ctx context.Context, id string) (*acme.Account, error) {
						assert.Equals(t, id, accID)
						return acc, nil
					},
				},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "account is not active"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{Status: "valid", Key: jwk}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				linker: acme.NewLinker("test.ca.smallstep.com", "acme"),
				db: &acme.MockDB{
					MockGetAccount: func(ctx context.Context, id string) (*acme.Account, error) {
						assert.Equals(t, id, accID)
						return acc, nil
					},
				},
				ctx: ctx,
				next: func(w http.ResponseWriter, r *http.Request) {
					_acc, err := accountFromContext(r.Context())
					assert.FatalError(t, err)
					assert.Equals(t, _acc, acc)
					_jwk, err := jwkFromContext(r.Context())
					assert.FatalError(t, err)
					assert.Equals(t, _jwk, jwk)
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := newBaseContext(tc.ctx, tc.db, tc.linker)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			lookupJWK(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_extractJWK(t *testing.T) {
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	kid, err := jwk.Thumbprint(crypto.SHA256)
	assert.FatalError(t, err)
	pub := jwk.Public()
	pub.KeyID = base64.RawURLEncoding.EncodeToString(kid)

	so := new(jose.SignerOptions)
	so.WithHeader("jwk", pub)
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk.Key,
	}, so)
	assert.FatalError(t, err)
	jws, err := signer.Sign([]byte("baz"))
	assert.FatalError(t, err)
	raw, err := jws.CompactSerialize()
	assert.FatalError(t, err)
	parsedJWS, err := jose.ParseJWS(raw)
	assert.FatalError(t, err)
	u := fmt.Sprintf("https://ca.smallstep.com/acme/%s/account/1234",
		provName)
	type test struct {
		db         acme.DB
		ctx        context.Context
		next       func(http.ResponseWriter, *http.Request)
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-jws": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        acme.NewProvisionerContext(context.Background(), prov),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jws": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jwk": func(t *testing.T) test {
			_jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							JSONWebKey: nil,
						},
					},
				},
			}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, _jws)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "jwk expected in protected header"),
			}
		},
		"fail/invalid-jwk": func(t *testing.T) test {
			_jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							JSONWebKey: &jose.JSONWebKey{Key: "foo"},
						},
					},
				},
			}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, _jws)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "invalid jwk in protected header"),
			}
		},
		"fail/GetAccountByKey-error": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				ctx: ctx,
				db: &acme.MockDB{
					MockGetAccountByKeyID: func(ctx context.Context, kid string) (*acme.Account, error) {
						assert.Equals(t, kid, pub.KeyID)
						return nil, acme.NewErrorISE("force")
					},
				},
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"fail/account-not-valid": func(t *testing.T) test {
			acc := &acme.Account{Status: "deactivated"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				ctx: ctx,
				db: &acme.MockDB{
					MockGetAccountByKeyID: func(ctx context.Context, kid string) (*acme.Account, error) {
						assert.Equals(t, kid, pub.KeyID)
						return acc, nil
					},
				},
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "account is not active"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{Status: "valid"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				ctx: ctx,
				db: &acme.MockDB{
					MockGetAccountByKeyID: func(ctx context.Context, kid string) (*acme.Account, error) {
						assert.Equals(t, kid, pub.KeyID)
						return acc, nil
					},
				},
				next: func(w http.ResponseWriter, r *http.Request) {
					_acc, err := accountFromContext(r.Context())
					assert.FatalError(t, err)
					assert.Equals(t, _acc, acc)
					_jwk, err := jwkFromContext(r.Context())
					assert.FatalError(t, err)
					assert.Equals(t, _jwk.KeyID, pub.KeyID)
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
		"ok/no-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				ctx: ctx,
				db: &acme.MockDB{
					MockGetAccountByKeyID: func(ctx context.Context, kid string) (*acme.Account, error) {
						assert.Equals(t, kid, pub.KeyID)
						return nil, acme.ErrNotFound
					},
				},
				next: func(w http.ResponseWriter, r *http.Request) {
					_acc, err := accountFromContext(r.Context())
					assert.NotNil(t, err)
					assert.Nil(t, _acc)
					_jwk, err := jwkFromContext(r.Context())
					assert.FatalError(t, err)
					assert.Equals(t, _jwk.KeyID, pub.KeyID)
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := newBaseContext(tc.ctx, tc.db)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			extractJWK(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_validateJWS(t *testing.T) {
	u := "https://ca.smallstep.com/acme/account/1234"
	type test struct {
		db         acme.DB
		ctx        context.Context
		next       func(http.ResponseWriter, *http.Request)
		err        *acme.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-jws": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.Background(),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jws": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, nil),
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/no-signature": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, &jose.JSONWebSignature{}),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "request body does not contain a signature"),
			}
		},
		"fail/more-than-one-signature": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{},
					{},
				},
			}
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "request body contains more than one signature"),
			}
		},
		"fail/unprotected-header-not-empty": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{Unprotected: jose.Header{Nonce: "abc"}},
				},
			}
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "unprotected header must not be used"),
			}
		},
		"fail/unsuitable-algorithm-none": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{Protected: jose.Header{Algorithm: "none"}},
				},
			}
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorBadSignatureAlgorithmType, "unsuitable algorithm: none"),
			}
		},
		"fail/unsuitable-algorithm-mac": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{Protected: jose.Header{Algorithm: jose.HS256}},
				},
			}
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorBadSignatureAlgorithmType, "unsuitable algorithm: %s", jose.HS256),
			}
		},
		"fail/rsa-key-&-alg-mismatch": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			pub := jwk.Public()
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm:  jose.RS256,
							JSONWebKey: &pub,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "jws key type and algorithm do not match"),
			}
		},
		"fail/rsa-key-too-small": func(t *testing.T) test {
			revert := keyutil.Insecure()
			defer revert()
			jwk, err := jose.GenerateJWK("RSA", "", "", "sig", "", 1024)
			assert.FatalError(t, err)
			pub := jwk.Public()
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm:  jose.RS256,
							JSONWebKey: &pub,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "rsa keys must be at least 2048 bits (256 bytes) in size"),
			}
		},
		"fail/UseNonce-error": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{Protected: jose.Header{Algorithm: jose.ES256}},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return acme.NewErrorISE("force")
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"fail/no-url-header": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{Protected: jose.Header{Algorithm: jose.ES256}},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "jws missing url protected header"),
			}
		},
		"fail/url-mismatch": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": "foo",
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "url header in JWS (foo) does not match request url (%s)", u),
			}
		},
		"fail/both-jwk-kid": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			pub := jwk.Public()
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm:  jose.ES256,
							KeyID:      "bar",
							JSONWebKey: &pub,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "jwk and kid are mutually exclusive"),
			}
		},
		"fail/no-jwk-kid": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, jws),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "either jwk or kid must be defined in jws protected header"),
			}
		},
		"ok/kid": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx: context.WithValue(context.Background(), jwsContextKey, jws),
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
		"ok/jwk/ecdsa": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			pub := jwk.Public()
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm:  jose.ES256,
							JSONWebKey: &pub,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx: context.WithValue(context.Background(), jwsContextKey, jws),
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
		"ok/jwk/rsa": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("RSA", "", "", "sig", "", 2048)
			assert.FatalError(t, err)
			pub := jwk.Public()
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm:  jose.RS256,
							JSONWebKey: &pub,
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": u,
							},
						},
					},
				},
			}
			return test{
				db: &acme.MockDB{
					MockDeleteNonce: func(ctx context.Context, n acme.Nonce) error {
						return nil
					},
				},
				ctx: context.WithValue(context.Background(), jwsContextKey, jws),
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := newBaseContext(tc.ctx, tc.db)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			validateJWS(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func Test_canExtractJWKFrom(t *testing.T) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	type args struct {
		jws *jose.JSONWebSignature
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no-jws",
			args: args{
				jws: nil,
			},
			want: false,
		},
		{
			name: "no-signatures",
			args: args{
				jws: &jose.JSONWebSignature{
					Signatures: []jose.Signature{},
				},
			},
			want: false,
		},
		{
			name: "no-jwk",
			args: args{
				jws: &jose.JSONWebSignature{
					Signatures: []jose.Signature{
						{
							Protected: jose.Header{},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ok",
			args: args{
				jws: &jose.JSONWebSignature{
					Signatures: []jose.Signature{
						{
							Protected: jose.Header{
								JSONWebKey: jwk,
							},
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canExtractJWKFrom(tt.args.jws); got != tt.want {
				t.Errorf("canExtractJWKFrom() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_extractOrLookupJWK(t *testing.T) {
	u := "https://ca.smallstep.com/acme/account"
	type test struct {
		db         acme.DB
		linker     acme.Linker
		statusCode int
		ctx        context.Context
		err        *acme.Error
		next       func(w http.ResponseWriter, r *http.Request)
	}
	var tests = map[string]func(t *testing.T) test{
		"ok/extract": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			kid, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)
			pub := jwk.Public()
			pub.KeyID = base64.RawURLEncoding.EncodeToString(kid)
			so := new(jose.SignerOptions)
			so.WithHeader("jwk", pub) // JWK for certificate private key flow
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			signed, err := signer.Sign([]byte("foo"))
			assert.FatalError(t, err)
			raw, err := signed.CompactSerialize()
			assert.FatalError(t, err)
			parsedJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			return test{
				linker: acme.NewLinker("dns", "acme"),
				db: &acme.MockDB{
					MockGetAccountByKeyID: func(ctx context.Context, kid string) (*acme.Account, error) {
						assert.Equals(t, kid, pub.KeyID)
						return nil, acme.ErrNotFound
					},
				},
				ctx:        context.WithValue(context.Background(), jwsContextKey, parsedJWS),
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
			}
		},
		"ok/lookup": func(t *testing.T) test {
			prov := newProv()
			provName := url.PathEscape(prov.GetName())
			baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			accID := "accID"
			prefix := fmt.Sprintf("%s/acme/%s/account/", baseURL, provName)
			so := new(jose.SignerOptions)
			so.WithHeader("kid", fmt.Sprintf("%s%s", prefix, accID)) // KID for account private key flow
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign([]byte("baz"))
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			parsedJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			acc := &acme.Account{ID: "accID", Key: jwk, Status: "valid"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				linker: acme.NewLinker("test.ca.smallstep.com", "acme"),
				db: &acme.MockDB{
					MockGetAccount: func(ctx context.Context, accID string) (*acme.Account, error) {
						assert.Equals(t, accID, acc.ID)
						return acc, nil
					},
				},
				ctx:        ctx,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := newBaseContext(tc.ctx, tc.db, tc.linker)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			extractOrLookupJWK(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}

func TestHandler_checkPrerequisites(t *testing.T) {
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	u := fmt.Sprintf("%s/acme/%s/account/1234",
		baseURL, provName)
	type test struct {
		linker               acme.Linker
		ctx                  context.Context
		prerequisitesChecker func(context.Context) (bool, error)
		next                 func(http.ResponseWriter, *http.Request)
		err                  *acme.Error
		statusCode           int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/error": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			return test{
				linker:               acme.NewLinker("dns", "acme"),
				ctx:                  ctx,
				prerequisitesChecker: func(context.Context) (bool, error) { return false, errors.New("force") },
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				err:        acme.WrapErrorISE(errors.New("force"), "error checking acme provisioner prerequisites"),
				statusCode: 500,
			}
		},
		"fail/prerequisites-nok": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			return test{
				linker:               acme.NewLinker("dns", "acme"),
				ctx:                  ctx,
				prerequisitesChecker: func(context.Context) (bool, error) { return false, nil },
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				err:        acme.NewError(acme.ErrorNotImplementedType, "acme provisioner configuration lacks prerequisites"),
				statusCode: 501,
			}
		},
		"ok": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			return test{
				linker:               acme.NewLinker("dns", "acme"),
				ctx:                  ctx,
				prerequisitesChecker: func(context.Context) (bool, error) { return true, nil },
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(testBody)
				},
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewPrerequisitesCheckerContext(tc.ctx, tc.prerequisitesChecker)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			checkPrerequisites(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))
				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), testBody)
			}
		})
	}
}
