package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
)

type mockAcmeAuthority struct {
	getLink         func(ctx context.Context, link acme.Link, absPath bool, ins ...string) string
	getLinkExplicit func(acme.Link, string, bool, *url.URL, ...string) string

	deactivateAccount func(ctx context.Context, accID string) (*acme.Account, error)
	getAccount        func(ctx context.Context, accID string) (*acme.Account, error)
	getAccountByKey   func(ctx context.Context, key *jose.JSONWebKey) (*acme.Account, error)
	newAccount        func(ctx context.Context, ao acme.AccountOptions) (*acme.Account, error)
	updateAccount     func(context.Context, string, []string) (*acme.Account, error)

	getChallenge      func(ctx context.Context, accID string, chID string) (*acme.Challenge, error)
	validateChallenge func(ctx context.Context, accID string, chID string, key *jose.JSONWebKey) (*acme.Challenge, error)
	getAuthz          func(ctx context.Context, accID string, authzID string) (*acme.Authz, error)
	getDirectory      func(ctx context.Context) (*acme.Directory, error)
	getCertificate    func(string, string) ([]byte, error)

	finalizeOrder      func(ctx context.Context, accID string, orderID string, csr *x509.CertificateRequest) (*acme.Order, error)
	getOrder           func(ctx context.Context, accID string, orderID string) (*acme.Order, error)
	getOrdersByAccount func(ctx context.Context, accID string) ([]string, error)
	newOrder           func(ctx context.Context, oo acme.OrderOptions) (*acme.Order, error)

	loadProvisionerByID func(string) (provisioner.Interface, error)
	newNonce            func() (string, error)
	useNonce            func(string) error
	ret1                interface{}
	err                 error
}

func (m *mockAcmeAuthority) DeactivateAccount(ctx context.Context, id string) (*acme.Account, error) {
	if m.deactivateAccount != nil {
		return m.deactivateAccount(ctx, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) FinalizeOrder(ctx context.Context, accID, id string, csr *x509.CertificateRequest) (*acme.Order, error) {
	if m.finalizeOrder != nil {
		return m.finalizeOrder(ctx, accID, id, csr)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetAccount(ctx context.Context, id string) (*acme.Account, error) {
	if m.getAccount != nil {
		return m.getAccount(ctx, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAccountByKey(ctx context.Context, jwk *jose.JSONWebKey) (*acme.Account, error) {
	if m.getAccountByKey != nil {
		return m.getAccountByKey(ctx, jwk)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAuthz(ctx context.Context, accID, id string) (*acme.Authz, error) {
	if m.getAuthz != nil {
		return m.getAuthz(ctx, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Authz), m.err
}

func (m *mockAcmeAuthority) GetCertificate(accID string, id string) ([]byte, error) {
	if m.getCertificate != nil {
		return m.getCertificate(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.([]byte), m.err
}

func (m *mockAcmeAuthority) GetChallenge(ctx context.Context, accID, id string) (*acme.Challenge, error) {
	if m.getChallenge != nil {
		return m.getChallenge(ctx, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Challenge), m.err
}

func (m *mockAcmeAuthority) GetDirectory(ctx context.Context) (*acme.Directory, error) {
	if m.getDirectory != nil {
		return m.getDirectory(ctx)
	}
	return m.ret1.(*acme.Directory), m.err
}

func (m *mockAcmeAuthority) GetLink(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
	if m.getLink != nil {
		return m.getLink(ctx, typ, abs, ins...)
	}
	return m.ret1.(string)
}

func (m *mockAcmeAuthority) GetLinkExplicit(typ acme.Link, provID string, abs bool, baseURL *url.URL, ins ...string) string {
	if m.getLinkExplicit != nil {
		return m.getLinkExplicit(typ, provID, abs, baseURL, ins...)
	}
	return m.ret1.(string)
}

func (m *mockAcmeAuthority) GetOrder(ctx context.Context, accID, id string) (*acme.Order, error) {
	if m.getOrder != nil {
		return m.getOrder(ctx, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetOrdersByAccount(ctx context.Context, id string) ([]string, error) {
	if m.getOrdersByAccount != nil {
		return m.getOrdersByAccount(ctx, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.([]string), m.err
}

func (m *mockAcmeAuthority) LoadProvisionerByID(provID string) (provisioner.Interface, error) {
	if m.loadProvisionerByID != nil {
		return m.loadProvisionerByID(provID)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *mockAcmeAuthority) NewAccount(ctx context.Context, ops acme.AccountOptions) (*acme.Account, error) {
	if m.newAccount != nil {
		return m.newAccount(ctx, ops)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) NewNonce() (string, error) {
	if m.newNonce != nil {
		return m.newNonce()
	} else if m.err != nil {
		return "", m.err
	}
	return m.ret1.(string), m.err
}

func (m *mockAcmeAuthority) NewOrder(ctx context.Context, ops acme.OrderOptions) (*acme.Order, error) {
	if m.newOrder != nil {
		return m.newOrder(ctx, ops)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) UpdateAccount(ctx context.Context, id string, contact []string) (*acme.Account, error) {
	if m.updateAccount != nil {
		return m.updateAccount(ctx, id, contact)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) UseNonce(nonce string) error {
	if m.useNonce != nil {
		return m.useNonce(nonce)
	}
	return m.err
}

func (m *mockAcmeAuthority) ValidateChallenge(ctx context.Context, accID string, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
	switch {
	case m.validateChallenge != nil:
		return m.validateChallenge(ctx, accID, id, jwk)
	case m.err != nil:
		return nil, m.err
	default:
		return m.ret1.(*acme.Challenge), m.err
	}
}

func TestHandlerGetNonce(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"GET", 204},
		{"HEAD", 200},
	}

	// Request with chi context
	req := httptest.NewRequest("GET", "http://ca.smallstep.com/nonce", nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(nil).(*Handler)
			w := httptest.NewRecorder()
			req.Method = tt.name
			h.GetNonce(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("Handler.GetNonce StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestHandlerGetDirectory(t *testing.T) {
	auth, err := acme.New(nil, acme.AuthorityOptions{
		DB:     new(db.MockNoSQLDB),
		DNS:    "ca.smallstep.com",
		Prefix: "acme",
	})
	assert.FatalError(t, err)

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)

	expDir := acme.Directory{
		NewNonce:   fmt.Sprintf("%s/acme/%s/new-nonce", baseURL.String(), provName),
		NewAccount: fmt.Sprintf("%s/acme/%s/new-account", baseURL.String(), provName),
		NewOrder:   fmt.Sprintf("%s/acme/%s/new-order", baseURL.String(), provName),
		RevokeCert: fmt.Sprintf("%s/acme/%s/revoke-cert", baseURL.String(), provName),
		KeyChange:  fmt.Sprintf("%s/acme/%s/key-change", baseURL.String(), provName),
	}

	type test struct {
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			return test{
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(auth).(*Handler)
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			h.GetDirectory(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				var ae acme.AError
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))
				prob := tc.problem.ToACME()

				assert.Equals(t, ae.Type, prob.Type)
				assert.Equals(t, ae.Detail, prob.Detail)
				assert.Equals(t, ae.Identifier, prob.Identifier)
				assert.Equals(t, ae.Subproblems, prob.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				var dir acme.Directory
				json.Unmarshal(bytes.TrimSpace(body), &dir)
				assert.Equals(t, dir, expDir)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandlerGetAuthz(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour)
	az := acme.Authz{
		ID: "authzID",
		Identifier: acme.Identifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:   "pending",
		Expires:  expiry.Format(time.RFC3339),
		Wildcard: false,
		Challenges: []*acme.Challenge{
			{
				Type:    "http-01",
				Status:  "pending",
				Token:   "tok2",
				URL:     "https://ca.smallstep.com/acme/challenge/chHTTPID",
				ID:      "chHTTP01ID",
				AuthzID: "authzID",
			},
			{
				Type:    "dns-01",
				Status:  "pending",
				Token:   "tok2",
				URL:     "https://ca.smallstep.com/acme/challenge/chDNSID",
				ID:      "chDNSID",
				AuthzID: "authzID",
			},
		},
	}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("authzID", az.ID)
	url := fmt.Sprintf("%s/acme/%s/challenge/%s",
		baseURL.String(), provName, az.ID)

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.WithValue(context.Background(), acme.ProvisionerContextKey, prov),
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getAuthz-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.ServerInternalErr(errors.New("force")),
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					getAuthz: func(ctx context.Context, accID, id string) (*acme.Authz, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, az.ID)
						return &az, nil
					},
					getLink: func(ctx context.Context, typ acme.Link, abs bool, in ...string) string {
						assert.Equals(t, typ, acme.AuthzLink)
						assert.Equals(t, acme.BaseURLFromContext(ctx), baseURL)
						assert.True(t, abs)
						assert.Equals(t, in, []string{az.ID})
						return url
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
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetAuthz(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				var ae acme.AError
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))
				prob := tc.problem.ToACME()

				assert.Equals(t, ae.Type, prob.Type)
				assert.Equals(t, ae.Detail, prob.Detail)
				assert.Equals(t, ae.Identifier, prob.Identifier)
				assert.Equals(t, ae.Subproblems, prob.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				//var gotAz acme.Authz
				//assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &gotAz))
				expB, err := json.Marshal(az)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{url})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandlerGetCertificate(t *testing.T) {
	leaf, err := pemutil.ReadCertificate("../../authority/testdata/certs/foo.crt")
	assert.FatalError(t, err)
	inter, err := pemutil.ReadCertificate("../../authority/testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	root, err := pemutil.ReadCertificate("../../authority/testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	certBytes := append(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	}), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: inter.Raw,
	})...)
	certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Raw,
	})...)
	certID := "certID"

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("certID", certID)
	url := fmt.Sprintf("%s/acme/%s/certificate/%s",
		baseURL.String(), provName, certID)

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.WithValue(context.Background(), acme.ProvisionerContextKey, prov),
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.AccContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getCertificate-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.ServerInternalErr(errors.New("force")),
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"fail/decode-leaf-for-loggger": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getCertificate: func(accID, id string) ([]byte, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, certID)
						return []byte("foo"), nil
					},
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("failed to decode any certificates from generated certBytes")),
			}
		},
		"fail/parse-x509-leaf-for-logger": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getCertificate: func(accID, id string) ([]byte, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, certID)
						return pem.EncodeToMemory(&pem.Block{
							Type:  "CERTIFICATE REQUEST",
							Bytes: []byte("foo"),
						}), nil
					},
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("failed to parse generated leaf certificate")),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getCertificate: func(accID, id string) ([]byte, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, certID)
						return certBytes, nil
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
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetCertificate(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				var ae acme.AError
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))
				prob := tc.problem.ToACME()

				assert.Equals(t, ae.Type, prob.Type)
				assert.HasPrefix(t, ae.Detail, prob.Detail)
				assert.Equals(t, ae.Identifier, prob.Identifier)
				assert.Equals(t, ae.Subproblems, prob.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.Equals(t, bytes.TrimSpace(body), bytes.TrimSpace(certBytes))
				assert.Equals(t, res.Header["Content-Type"], []string{"application/pem-certificate-chain; charset=utf-8"})
			}
		})
	}
}

func ch() acme.Challenge {
	return acme.Challenge{
		Type:    "http-01",
		Status:  "pending",
		Token:   "tok2",
		URL:     "https://ca.smallstep.com/acme/challenge/chID",
		ID:      "chID",
		AuthzID: "authzID",
	}
}

func TestHandlerGetChallenge(t *testing.T) {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("chID", "chID")
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	url := fmt.Sprintf("%s/acme/challenge/%s", baseURL, "chID")

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		ch         acme.Challenge
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), acme.ProvisionerContextKey, prov),
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/validate-challenge-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{isEmptyJSON: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.UnauthorizedErr(nil),
				},
				ctx:        ctx,
				statusCode: 401,
				problem:    acme.UnauthorizedErr(nil),
			}
		},
		"fail/get-challenge-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{isPostAsGet: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.UnauthorizedErr(nil),
				},
				ctx:        ctx,
				statusCode: 401,
				problem:    acme.UnauthorizedErr(nil),
			}
		},
		"ok/validate-challenge": func(t *testing.T) test {
			key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{ID: "accID", Key: key}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{isEmptyJSON: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			ch := ch()
			ch.Status = "valid"
			ch.Validated = time.Now().UTC().Format(time.RFC3339)
			count := 0
			return test{
				auth: &mockAcmeAuthority{
					validateChallenge: func(ctx context.Context, accID, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, ch.ID)
						assert.Equals(t, jwk.KeyID, key.KeyID)
						return &ch, nil
					},
					getLink: func(ctx context.Context, typ acme.Link, abs bool, in ...string) string {
						var ret string
						switch count {
						case 0:
							assert.Equals(t, typ, acme.AuthzLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.AuthzID})
							ret = fmt.Sprintf("%s/acme/%s/authz/%s", baseURL.String(), provName, ch.AuthzID)
						case 1:
							assert.Equals(t, typ, acme.ChallengeLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.ID})
							ret = url
						}
						count++
						return ret
					},
				},
				ctx:        ctx,
				statusCode: 200,
				ch:         ch,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetChallenge(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				var ae acme.AError
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))
				prob := tc.problem.ToACME()

				assert.Equals(t, ae.Type, prob.Type)
				assert.Equals(t, ae.Detail, prob.Detail)
				assert.Equals(t, ae.Identifier, prob.Identifier)
				assert.Equals(t, ae.Subproblems, prob.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				expB, err := json.Marshal(tc.ch)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Link"], []string{fmt.Sprintf("<%s/acme/%s/authz/%s>;rel=\"up\"", baseURL, provName, tc.ch.AuthzID)})
				assert.Equals(t, res.Header["Location"], []string{url})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
