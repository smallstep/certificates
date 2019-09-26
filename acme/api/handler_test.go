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
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
)

type mockAcmeAuthority struct {
	deactivateAccount   func(provisioner.Interface, string) (*acme.Account, error)
	finalizeOrder       func(p provisioner.Interface, accID string, id string, csr *x509.CertificateRequest) (*acme.Order, error)
	getAccount          func(p provisioner.Interface, id string) (*acme.Account, error)
	getAccountByKey     func(provisioner.Interface, *jose.JSONWebKey) (*acme.Account, error)
	getAuthz            func(p provisioner.Interface, accID string, id string) (*acme.Authz, error)
	getCertificate      func(accID string, id string) ([]byte, error)
	getChallenge        func(p provisioner.Interface, accID string, id string) (*acme.Challenge, error)
	getDirectory        func(provisioner.Interface) *acme.Directory
	getLink             func(acme.Link, string, bool, ...string) string
	getOrder            func(p provisioner.Interface, accID string, id string) (*acme.Order, error)
	getOrdersByAccount  func(p provisioner.Interface, id string) ([]string, error)
	loadProvisionerByID func(string) (provisioner.Interface, error)
	newAccount          func(provisioner.Interface, acme.AccountOptions) (*acme.Account, error)
	newNonce            func() (string, error)
	newOrder            func(provisioner.Interface, acme.OrderOptions) (*acme.Order, error)
	updateAccount       func(provisioner.Interface, string, []string) (*acme.Account, error)
	useNonce            func(string) error
	validateChallenge   func(p provisioner.Interface, accID string, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error)
	ret1                interface{}
	err                 error
}

func (m *mockAcmeAuthority) DeactivateAccount(p provisioner.Interface, id string) (*acme.Account, error) {
	if m.deactivateAccount != nil {
		return m.deactivateAccount(p, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) FinalizeOrder(p provisioner.Interface, accID, id string, csr *x509.CertificateRequest) (*acme.Order, error) {
	if m.finalizeOrder != nil {
		return m.finalizeOrder(p, accID, id, csr)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetAccount(p provisioner.Interface, id string) (*acme.Account, error) {
	if m.getAccount != nil {
		return m.getAccount(p, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAccountByKey(p provisioner.Interface, jwk *jose.JSONWebKey) (*acme.Account, error) {
	if m.getAccountByKey != nil {
		return m.getAccountByKey(p, jwk)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAuthz(p provisioner.Interface, accID, id string) (*acme.Authz, error) {
	if m.getAuthz != nil {
		return m.getAuthz(p, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Authz), m.err
}

func (m *mockAcmeAuthority) GetCertificate(accID, id string) ([]byte, error) {
	if m.getCertificate != nil {
		return m.getCertificate(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.([]byte), m.err
}

func (m *mockAcmeAuthority) GetChallenge(p provisioner.Interface, accID, id string) (*acme.Challenge, error) {
	if m.getChallenge != nil {
		return m.getChallenge(p, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Challenge), m.err
}

func (m *mockAcmeAuthority) GetDirectory(p provisioner.Interface) *acme.Directory {
	if m.getDirectory != nil {
		return m.getDirectory(p)
	}
	return m.ret1.(*acme.Directory)
}

func (m *mockAcmeAuthority) GetLink(typ acme.Link, provID string, abs bool, in ...string) string {
	if m.getLink != nil {
		return m.getLink(typ, provID, abs, in...)
	}
	return m.ret1.(string)
}

func (m *mockAcmeAuthority) GetOrder(p provisioner.Interface, accID, id string) (*acme.Order, error) {
	if m.getOrder != nil {
		return m.getOrder(p, accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetOrdersByAccount(p provisioner.Interface, id string) ([]string, error) {
	if m.getOrdersByAccount != nil {
		return m.getOrdersByAccount(p, id)
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

func (m *mockAcmeAuthority) NewAccount(p provisioner.Interface, ops acme.AccountOptions) (*acme.Account, error) {
	if m.newAccount != nil {
		return m.newAccount(p, ops)
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

func (m *mockAcmeAuthority) NewOrder(p provisioner.Interface, ops acme.OrderOptions) (*acme.Order, error) {
	if m.newOrder != nil {
		return m.newOrder(p, ops)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) UpdateAccount(p provisioner.Interface, id string, contact []string) (*acme.Account, error) {
	if m.updateAccount != nil {
		return m.updateAccount(p, id, contact)
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

func (m *mockAcmeAuthority) ValidateChallenge(p provisioner.Interface, accID string, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
	switch {
	case m.validateChallenge != nil:
		return m.validateChallenge(p, accID, id, jwk)
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
	auth := acme.NewAuthority(nil, "ca.smallstep.com", "acme", nil)
	prov := newProv()
	url := fmt.Sprintf("http://ca.smallstep.com/acme/%s/directory", acme.URLSafeProvisionerName(prov))

	expDir := acme.Directory{
		NewNonce:   fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-nonce", acme.URLSafeProvisionerName(prov)),
		NewAccount: fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-account", acme.URLSafeProvisionerName(prov)),
		NewOrder:   fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-order", acme.URLSafeProvisionerName(prov)),
		RevokeCert: fmt.Sprintf("https://ca.smallstep.com/acme/%s/revoke-cert", acme.URLSafeProvisionerName(prov)),
		KeyChange:  fmt.Sprintf("https://ca.smallstep.com/acme/%s/key-change", acme.URLSafeProvisionerName(prov)),
	}

	type test struct {
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			return test{
				ctx:        context.Background(),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, nil),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
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

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("authzID", az.ID)
	url := fmt.Sprintf("http://ca.smallstep.com/acme/%s/challenge/%s",
		acme.URLSafeProvisionerName(prov), az.ID)

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.Background(),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.WithValue(context.Background(), provisionerContextKey, nil),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/no-account": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getAuthz-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getAuthz: func(p provisioner.Interface, accID, id string) (*acme.Authz, error) {
						assert.Equals(t, p, prov)
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, az.ID)
						return &az, nil
					},
					getLink: func(typ acme.Link, provID string, abs bool, in ...string) string {
						assert.Equals(t, provID, acme.URLSafeProvisionerName(prov))
						assert.Equals(t, typ, acme.AuthzLink)
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
			req := httptest.NewRequest("GET", url, nil)
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
	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("certID", certID)
	url := fmt.Sprintf("http://ca.smallstep.com/acme/%s/certificate/%s",
		acme.URLSafeProvisionerName(prov), certID)

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
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getCertificate-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
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
			ctx := context.WithValue(context.Background(), accContextKey, acc)
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
				assert.Equals(t, ae.Detail, prob.Detail)
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
	url := fmt.Sprintf("http://ca.smallstep.com/acme/challenge/%s", "chID")
	prov := newProv()

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		ch         acme.Challenge
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			return test{
				ctx:        context.Background(),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, nil),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/no-account": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), provisionerContextKey, prov),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
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
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/validate-challenge-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isEmptyJSON: true})
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isPostAsGet: true})
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isEmptyJSON: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ch := ch()
			ch.Status = "valid"
			ch.Validated = time.Now().UTC().Format(time.RFC3339)
			count := 0
			return test{
				auth: &mockAcmeAuthority{
					validateChallenge: func(p provisioner.Interface, accID, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
						assert.Equals(t, p, prov)
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, ch.ID)
						assert.Equals(t, jwk.KeyID, key.KeyID)
						return &ch, nil
					},
					getLink: func(typ acme.Link, provID string, abs bool, in ...string) string {
						var ret string
						switch count {
						case 0:
							assert.Equals(t, typ, acme.AuthzLink)
							assert.Equals(t, provID, acme.URLSafeProvisionerName(prov))
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.AuthzID})
							ret = fmt.Sprintf("https://ca.smallstep.com/acme/authz/%s", ch.AuthzID)
						case 1:
							assert.Equals(t, typ, acme.ChallengeLink)
							assert.Equals(t, provID, acme.URLSafeProvisionerName(prov))
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
				assert.Equals(t, res.Header["Link"], []string{fmt.Sprintf("<https://ca.smallstep.com/acme/authz/%s>;rel=\"up\"", tc.ch.AuthzID)})
				assert.Equals(t, res.Header["Location"], []string{url})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
