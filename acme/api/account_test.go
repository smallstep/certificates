package api

import (
	"bytes"
	"context"
	"encoding/json"
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
	"go.step.sm/crypto/jose"
)

var (
	defaultDisableRenewal   = false
	globalProvisionerClaims = provisioner.Claims{
		MinTLSDur:      &provisioner.Duration{Duration: 5 * time.Minute},
		MaxTLSDur:      &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultTLSDur:  &provisioner.Duration{Duration: 24 * time.Hour},
		DisableRenewal: &defaultDisableRenewal,
	}
)

func newProv() provisioner.Interface {
	// Initialize provisioners
	p := &provisioner.ACME{
		Type: "ACME",
		Name: "test@acme-provisioner.com",
	}
	if err := p.Init(provisioner.Config{Claims: globalProvisionerClaims}); err != nil {
		fmt.Printf("%v", err)
	}
	return p
}

func TestNewAccountRequestValidate(t *testing.T) {
	type test struct {
		nar *NewAccountRequest
		err *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/incompatible-input": func(t *testing.T) test {
			return test{
				nar: &NewAccountRequest{
					OnlyReturnExisting: true,
					Contact:            []string{"foo", "bar"},
				},
				err: acme.MalformedErr(errors.Errorf("incompatible input; onlyReturnExisting must be alone")),
			}
		},
		"fail/bad-contact": func(t *testing.T) test {
			return test{
				nar: &NewAccountRequest{
					Contact: []string{"foo", ""},
				},
				err: acme.MalformedErr(errors.Errorf("contact cannot be empty string")),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				nar: &NewAccountRequest{
					Contact: []string{"foo", "bar"},
				},
			}
		},
		"ok/onlyReturnExisting": func(t *testing.T) test {
			return test{
				nar: &NewAccountRequest{
					OnlyReturnExisting: true,
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := tc.nar.Validate(); err != nil {
				if assert.NotNil(t, err) {
					ae, ok := err.(*acme.Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestUpdateAccountRequestValidate(t *testing.T) {
	type test struct {
		uar *UpdateAccountRequest
		err *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/incompatible-input": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Contact: []string{"foo", "bar"},
					Status:  "foo",
				},
				err: acme.MalformedErr(errors.Errorf("incompatible input; " +
					"contact and status updates are mutually exclusive")),
			}
		},
		"fail/bad-contact": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Contact: []string{"foo", ""},
				},
				err: acme.MalformedErr(errors.Errorf("contact cannot be empty string")),
			}
		},
		"fail/bad-status": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Status: "foo",
				},
				err: acme.MalformedErr(errors.Errorf("cannot update account " +
					"status to foo, only deactivated")),
			}
		},
		"ok/contact": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Contact: []string{"foo", "bar"},
				},
			}
		},
		"ok/status": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Status: "deactivated",
				},
			}
		},
		"ok/accept-empty": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := tc.uar.Validate(); err != nil {
				if assert.NotNil(t, err) {
					ae, ok := err.(*acme.Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestHandlerGetOrdersByAccount(t *testing.T) {
	oids := []string{
		"https://ca.smallstep.com/acme/order/foo",
		"https://ca.smallstep.com/acme/order/bar",
	}
	accID := "account-id"
	prov := newProv()

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("accID", accID)
	url := fmt.Sprintf("http://ca.smallstep.com/acme/account/%s/orders", accID)

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
		"fail/account-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "foo"}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 401,
				problem:    acme.UnauthorizedErr(errors.New("account ID does not match url param")),
			}
		},
		"fail/getOrdersByAccount-error": func(t *testing.T) test {
			acc := &acme.Account{ID: accID}
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
			acc := &acme.Account{ID: accID}
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getOrdersByAccount: func(ctx context.Context, id string) ([]string, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, id, acc.ID)
						return oids, nil
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
			h.GetOrdersByAccount(w, req)
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
				expB, err := json.Marshal(oids)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandlerNewAccount(t *testing.T) {
	accID := "accountID"
	acc := acme.Account{
		ID:     accID,
		Status: "valid",
		Orders: fmt.Sprintf("https://ca.smallstep.com/acme/account/%s/orders", accID),
	}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-payload": func(t *testing.T) test {
			return test{
				ctx:        context.WithValue(context.Background(), acme.ProvisionerContextKey, prov),
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.MalformedErr(errors.New("failed to unmarshal new-account request payload: unexpected end of JSON input")),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", ""},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.MalformedErr(errors.New("contact cannot be empty string")),
			}
		},
		"fail/no-existing-account": func(t *testing.T) test {
			nar := &NewAccountRequest{
				OnlyReturnExisting: true,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/no-jwk": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.Errorf("jwk expected in request context")),
			}
		},
		"fail/nil-jwk": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.JwkContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.Errorf("jwk expected in request context")),
			}
		},
		"fail/NewAccount-error": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.JwkContextKey, jwk)
			return test{
				auth: &mockAcmeAuthority{
					newAccount: func(ctx context.Context, ops acme.AccountOptions) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, ops.Contact, nar.Contact)
						assert.Equals(t, ops.Key, jwk)
						return nil, acme.ServerInternalErr(errors.New("force"))
					},
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"ok/new-account": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.JwkContextKey, jwk)
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					newAccount: func(ctx context.Context, ops acme.AccountOptions) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, ops.Contact, nar.Contact)
						assert.Equals(t, ops.Key, jwk)
						return &acc, nil
					},
					getLink: func(ctx context.Context, typ acme.Link, abs bool, in ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.True(t, abs)
						assert.Equals(t, baseURL, acme.BaseURLFromContext(ctx))
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL.String(), provName, accID)
					},
				},
				ctx:        ctx,
				statusCode: 201,
			}
		},
		"ok/return-existing": func(t *testing.T) test {
			nar := &NewAccountRequest{
				OnlyReturnExisting: true,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					getLink: func(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.Equals(t, baseURL, acme.BaseURLFromContext(ctx))
						assert.Equals(t, ins, []string{accID})
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL.String(), provName, accID)
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
			h.NewAccount(w, req)
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
				expB, err := json.Marshal(acc)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/account/%s", baseURL.String(),
						provName, accID)})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandlerGetUpdateAccount(t *testing.T) {
	accID := "accountID"
	acc := acme.Account{
		ID:     accID,
		Status: "valid",
		Orders: fmt.Sprintf("https://ca.smallstep.com/acme/account/%s/orders", accID),
	}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
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
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.MalformedErr(errors.New("failed to unmarshal new-account request payload: unexpected end of JSON input")),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Contact: []string{"foo", ""},
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.MalformedErr(errors.New("contact cannot be empty string")),
			}
		},
		"fail/Deactivate-error": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Status: "deactivated",
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				auth: &mockAcmeAuthority{
					deactivateAccount: func(ctx context.Context, id string) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, id, accID)
						return nil, acme.ServerInternalErr(errors.New("force"))
					},
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"fail/UpdateAccount-error": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			return test{
				auth: &mockAcmeAuthority{
					updateAccount: func(ctx context.Context, id string, contacts []string) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, id, accID)
						assert.Equals(t, contacts, uar.Contact)
						return nil, acme.ServerInternalErr(errors.New("force"))
					},
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"ok/deactivate": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Status: "deactivated",
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					deactivateAccount: func(ctx context.Context, id string) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, id, accID)
						return &acc, nil
					},
					getLink: func(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.Equals(t, acme.BaseURLFromContext(ctx), baseURL)
						assert.Equals(t, ins, []string{accID})
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL.String(), provName, accID)
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
		"ok/update-empty": func(t *testing.T) test {
			uar := &UpdateAccountRequest{}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					getLink: func(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.Equals(t, acme.BaseURLFromContext(ctx), baseURL)
						assert.Equals(t, ins, []string{accID})
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL.String(), provName, accID)
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
		"ok/update-contacts": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					updateAccount: func(ctx context.Context, id string, contacts []string) (*acme.Account, error) {
						p, err := acme.ProvisionerFromContext(ctx)
						assert.FatalError(t, err)
						assert.Equals(t, p, prov)
						assert.Equals(t, id, accID)
						assert.Equals(t, contacts, uar.Contact)
						return &acc, nil
					},
					getLink: func(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.Equals(t, acme.BaseURLFromContext(ctx), baseURL)
						assert.Equals(t, ins, []string{accID})
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL.String(), provName, accID)
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
		"ok/post-as-get": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), acme.ProvisionerContextKey, prov)
			ctx = context.WithValue(ctx, acme.AccContextKey, &acc)
			ctx = context.WithValue(ctx, acme.PayloadContextKey, &payloadInfo{isPostAsGet: true})
			ctx = context.WithValue(ctx, acme.BaseURLContextKey, baseURL)
			return test{
				auth: &mockAcmeAuthority{
					getLink: func(ctx context.Context, typ acme.Link, abs bool, ins ...string) string {
						assert.Equals(t, typ, acme.AccountLink)
						assert.True(t, abs)
						assert.Equals(t, acme.BaseURLFromContext(ctx), baseURL)
						assert.Equals(t, ins, []string{accID})
						return fmt.Sprintf("%s/acme/%s/account/%s",
							baseURL, provName, accID)
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
			h.GetUpdateAccount(w, req)
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
				expB, err := json.Marshal(acc)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/account/%s", baseURL.String(),
						provName, accID)})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
