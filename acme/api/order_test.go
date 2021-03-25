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

func TestNewOrderRequest_Validate(t *testing.T) {
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
	now := clock.Now()
	nbf := now
	naf := now.Add(24 * time.Hour)
	expiry := now.Add(-time.Hour)
	o := acme.Order{
		ID:        "orderID",
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
		ExpiresAt: expiry,
		Status:    acme.StatusInvalid,
		Error:     acme.NewError(acme.ErrorMalformedType, "order has expired"),
		AuthorizationURLs: []string{
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/foo",
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/bar",
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/baz",
		},
		FinalizeURL: "https://test.ca.smallstep.com/acme/test@acme-provisioner.com/order/orderID/finalize",
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
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, nil)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/db.GetOrder-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
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
		"fail/account-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{AccountID: "foo"}, nil
					},
				},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "account id mismatch"),
			}
		},
		"fail/provisioner-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{AccountID: "accountID", ProvisionerID: "bar"}, nil
					},
				},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "provisioner id mismatch"),
			}
		},
		"fail/order-update-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							AccountID:     "accountID",
							ProvisionerID: "acme/test@acme-provisioner.com",
							ExpiresAt:     clock.Now().Add(-time.Hour),
							Status:        acme.StatusReady,
						}, nil
					},
					MockUpdateOrder: func(ctx context.Context, o *acme.Order) error {
						return acme.NewErrorISE("force")
					},
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							ID:               "orderID",
							AccountID:        "accountID",
							ProvisionerID:    "acme/test@acme-provisioner.com",
							ExpiresAt:        expiry,
							Status:           acme.StatusReady,
							AuthorizationIDs: []string{"foo", "bar", "baz"},
							NotBefore:        nbf,
							NotAfter:         naf,
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
						}, nil
					},
					MockUpdateOrder: func(ctx context.Context, o *acme.Order) error {
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
			h := &Handler{linker: NewLinker("dns", "acme"), db: tc.db}
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

/*
func TestHandler_NewOrder(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour)
	nbf := time.Now().UTC().Add(5 * time.Hour)
	naf := nbf.Add(17 * time.Hour)
	o := acme.Order{
		ID:        "orderID",
		ExpiresAt: expiry,
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
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner expected in request context"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, nil)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner expected in request context"),
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
						o.ID = "orderID"
						return nil
					},
				},
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
				ctx:        ctx,
				statusCode: 201,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{linker: NewLinker("dns", "prefix"), db: tc.db}
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
*/

func TestHandler_FinalizeOrder(t *testing.T) {
	now := clock.Now()
	nbf := now
	naf := now.Add(24 * time.Hour)
	o := acme.Order{
		ID:        "orderID",
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
		ExpiresAt: naf,
		Status:    acme.StatusValid,
		AuthorizationURLs: []string{
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/foo",
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/bar",
			"https://test.ca.smallstep.com/acme/test@acme-provisioner.com/authz/baz",
		},
		FinalizeURL:    "https://test.ca.smallstep.com/acme/test@acme-provisioner.com/order/orderID/finalize",
		CertificateURL: "https://test.ca.smallstep.com/acme/test@acme-provisioner.com/certificate/certID",
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", o.ID)
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	url := fmt.Sprintf("%s/acme/%s/order/%s",
		baseURL.String(), provName, o.ID)

	_csr, err := pemutil.Read("../../authority/testdata/certs/foo.csr")
	assert.FatalError(t, err)
	csr, ok := _csr.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	nor := &FinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
	}
	payloadBytes, err := json.Marshal(nor)
	assert.FatalError(t, err)

	type test struct {
		db         acme.DB
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
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, nil)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("paylod does not exist"),
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
		"fail/db.GetOrder-error": func(t *testing.T) test {

			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
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
		"fail/account-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{AccountID: "foo"}, nil
					},
				},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "account id mismatch"),
			}
		},
		"fail/provisioner-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{AccountID: "accountID", ProvisionerID: "bar"}, nil
					},
				},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "provisioner id mismatch"),
			}
		},
		"fail/order-finalize-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							AccountID:     "accountID",
							ProvisionerID: "acme/test@acme-provisioner.com",
							ExpiresAt:     clock.Now().Add(-time.Hour),
							Status:        acme.StatusReady,
						}, nil
					},
					MockUpdateOrder: func(ctx context.Context, o *acme.Order) error {
						return acme.NewErrorISE("force")
					},
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							ID:               "orderID",
							AccountID:        "accountID",
							ProvisionerID:    "acme/test@acme-provisioner.com",
							ExpiresAt:        naf,
							Status:           acme.StatusValid,
							AuthorizationIDs: []string{"foo", "bar", "baz"},
							NotBefore:        nbf,
							NotAfter:         naf,
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
							CertificateID: "certID",
						}, nil
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
			h := &Handler{linker: NewLinker("dns", "acme"), db: tc.db}
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

				ro := new(acme.Order)
				err = json.Unmarshal(body, ro)

				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{url})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
