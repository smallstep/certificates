package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"go.step.sm/crypto/pemutil"
)

func TestNewOrderRequestValidate(t *testing.T) {
	type test struct {
		nor      *NewOrderRequest
		nbf, naf time.Time
		err      *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-identifiers": func(t *testing.T) test {
			return test{
				nor: &NewOrderRequest{},
				err: acme.NewError(acme.ErrorMalformedType, "identifiers list cannot be empty"),
			}
		},
		"fail/bad-identifier": func(t *testing.T) test {
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "example.com"},
						{Type: "foo", Value: "bar.com"},
					},
				},
				err: acme.NewError(acme.ErrorMalformedType, "identifier type unsupported: foo"),
			}
		},
		"ok": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "example.com"},
						{Type: "dns", Value: "bar.com"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := tc.nor.Validate(); err != nil {
				if assert.NotNil(t, err) {
					ae, ok := err.(*acme.Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					if tc.nbf.IsZero() {
						assert.True(t, tc.nor.NotBefore.Before(time.Now().Add(time.Minute)))
						assert.True(t, tc.nor.NotBefore.After(time.Now().Add(-time.Minute)))
					} else {
						assert.Equals(t, tc.nor.NotBefore, tc.nbf)
					}
					if tc.naf.IsZero() {
						assert.True(t, tc.nor.NotAfter.Before(time.Now().Add(24*time.Hour)))
						assert.True(t, tc.nor.NotAfter.After(time.Now().Add(24*time.Hour-time.Minute)))
					} else {
						assert.Equals(t, tc.nor.NotAfter, tc.naf)
					}
				}
			}
		})
	}
}

func TestFinalizeRequestValidate(t *testing.T) {
	_csr, err := pemutil.Read("../../authority/testdata/certs/foo.csr")
	assert.FatalError(t, err)
	csr, ok := _csr.(*x509.CertificateRequest)
	assert.Fatal(t, ok)
	type test struct {
		fr  *FinalizeRequest
		err *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/parse-csr-error": func(t *testing.T) test {
			return test{
				fr:  &FinalizeRequest{},
				err: acme.NewError(acme.ErrorMalformedType, "unable to parse csr: asn1: syntax error: sequence truncated"),
			}
		},
		"fail/invalid-csr-signature": func(t *testing.T) test {
			b, err := pemutil.Read("../../authority/testdata/certs/badsig.csr")
			assert.FatalError(t, err)
			c, ok := b.(*x509.CertificateRequest)
			assert.Fatal(t, ok)
			return test{
				fr: &FinalizeRequest{
					CSR: base64.RawURLEncoding.EncodeToString(c.Raw),
				},
				err: acme.NewError(acme.ErrorMalformedType, "csr failed signature check: x509: ECDSA verification failure"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				fr: &FinalizeRequest{
					CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := tc.fr.Validate(); err != nil {
				if assert.NotNil(t, err) {
					ae, ok := err.(*acme.Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.fr.csr.Raw, csr.Raw)
				}
			}
		})
	}
}

func TestHandler_GetOrder(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour)
	nbf := time.Now().UTC()
	naf := time.Now().UTC().Add(24 * time.Hour)
	o := acme.Order{
		ID:        "orderID",
		Expires:   expiry,
		NotBefore: nbf,
		NotAfter:  naf,
		Identifiers: []acme.Identifier{
			{
				Type:  "dns",
				Value: "example.com",
			},
			{
				Type:  "dns",
				Value: "*.smallstep.com",
			},
		},
		Status:            "pending",
		AuthorizationURLs: []string{"foo", "bar"},
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", o.ID)
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	url := fmt.Sprintf("%s/acme/%s/order/%s",
		baseURL.String(), provName, o.ID)

	type test struct {
		db         acme.DB
		linker     Linker
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/getOrder-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockError: acme.NewErrorISE("force"),
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						assert.Equals(t, id, o.ID)
						return &o, nil
					},
				},
				linker:     NewLinker("dns", "acme"),
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{linker: tc.linker, db: tc.db}
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetOrder(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
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
				expB, err := json.Marshal(o)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{url})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandlerNewOrder(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour)
	nbf := time.Now().UTC().Add(5 * time.Hour)
	naf := nbf.Add(17 * time.Hour)
	o := acme.Order{
		ID:        "orderID",
		Expires:   expiry,
		NotBefore: nbf,
		NotAfter:  naf,
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "example.com"},
			{Type: "dns", Value: "bar.com"},
		},
		Status:            "pending",
		AuthorizationURLs: []string{"foo", "bar"},
	}

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	url := fmt.Sprintf("%s/acme/%s/new-order",
		baseURL.String(), provName)

	type test struct {
		db         acme.DB
		linker     Linker
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "failed to unmarshal new-order request payload: unexpected end of JSON input"),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "identifiers list cannot be empty"),
			}
		},
		"fail/NewOrder-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "example.com"},
					{Type: "dns", Value: "bar.com"},
				},
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db: &acme.MockDB{
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						return acme.NewError(acme.ErrorMalformedType, "force")
					},
				},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "example.com"},
					{Type: "dns", Value: "bar.com"},
				},
				NotBefore: nbf,
				NotAfter:  naf,
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				db: &acme.MockDB{
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						return nil
					},
				},
				linker:     NewLinker("dns", "acme"),
				ctx:        ctx,
				statusCode: 201,
			}
		},
		"ok/default-naf-nbf": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "example.com"},
					{Type: "dns", Value: "bar.com"},
				},
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				db: &acme.MockDB{
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						return nil
					},
				},
				linker:     NewLinker("dns", "acme"),
				ctx:        ctx,
				statusCode: 201,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{linker: tc.linker, db: tc.db}
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.NewOrder(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
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
				expB, err := json.Marshal(o)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/order/%s", baseURL.String(),
						provName, o.ID)})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_FinalizeOrder(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour)
	nbf := time.Now().UTC().Add(5 * time.Hour)
	naf := nbf.Add(17 * time.Hour)
	o := acme.Order{
		ID:        "orderID",
		Expires:   expiry,
		NotBefore: nbf,
		NotAfter:  naf,
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "example.com"},
			{Type: "dns", Value: "bar.com"},
		},
		Status:            "valid",
		AuthorizationURLs: []string{"foo", "bar"},
		CertificateURL:    "https://ca.smallstep.com/acme/certificate/certID",
	}
	_csr, err := pemutil.Read("../../authority/testdata/certs/foo.csr")
	assert.FatalError(t, err)
	csr, ok := _csr.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", o.ID)
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	url := fmt.Sprintf("%s/acme/%s/order/%s/finalize",
		baseURL.String(), provName, o.ID)

	type test struct {
		db         acme.DB
		linker     Linker
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "failed to unmarshal finalize-order request payload: unexpected end of JSON input"),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			fr := &FinalizeRequest{}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "unable to parse csr: asn1: syntax error: sequence truncated"),
			}
		},
		"fail/FinalizeOrder-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &FinalizeRequest{
				CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockUpdateOrder: func(ctx context.Context, o *acme.Order) error {
						/*
							p, err := acme.ProvisionerFromContext(ctx)
							assert.FatalError(t, err)
							assert.Equals(t, p, prov)
							assert.Equals(t, accID, acc.ID)
							assert.Equals(t, id, o.ID)
							assert.Equals(t, incsr.Raw, csr.Raw)
						*/
						return acme.NewError(acme.ErrorMalformedType, "force")
					},
				},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &FinalizeRequest{
				CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				linker: NewLinker("dns", "acme"),
				db: &acme.MockDB{
					MockUpdateOrder: func(ctx context.Context, o *acme.Order) error {
						/*
							p, err := acme.ProvisionerFromContext(ctx)
							assert.FatalError(t, err)
							assert.Equals(t, p, prov)
							assert.Equals(t, accID, acc.ID)
							assert.Equals(t, id, o.ID)
							assert.Equals(t, incsr.Raw, csr.Raw)
							return &o, nil
						*/
						return nil
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{linker: tc.linker, db: tc.db}
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.FinalizeOrder(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
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
				expB, err := json.Marshal(o)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/order/%s",
						baseURL, provName, o.ID)})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
