package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"

	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
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
		"fail/bad-identifier/bad-dns": func(t *testing.T) test {
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "xn--bücher.example.com"},
					},
				},
				err: acme.NewError(acme.ErrorMalformedType, "invalid DNS name: xn--bücher.example.com"),
			}
		},
		"fail/bad-identifier/dns-port": func(t *testing.T) test {
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "example.com:8080"},
					},
				},
				err: acme.NewError(acme.ErrorMalformedType, "invalid DNS name: example.com:8080"),
			}
		},
		"fail/bad-identifier/dns-wildcard-port": func(t *testing.T) test {
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "*.example.com:8080"},
					},
				},
				err: acme.NewError(acme.ErrorMalformedType, "invalid DNS name: *.example.com:8080"),
			}
		},
		"fail/bad-ip": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "ip", Value: "192.168.42.1000"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
				err: acme.NewError(acme.ErrorMalformedType, "invalid IP address: %s", "192.168.42.1000"),
			}
		},
		"ok": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "example.com"},
						{Type: "dns", Value: "*.bar.com"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
			}
		},
		"ok/ipv4": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "ip", Value: "192.168.42.42"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
			}
		},
		"ok/ipv6": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "ip", Value: "2001:db8::1"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
			}
		},
		"ok/mixed-dns-and-ipv4": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "example.com"},
						{Type: "ip", Value: "192.168.42.42"},
					},
					NotAfter:  naf,
					NotBefore: nbf,
				},
				nbf: nbf,
				naf: naf,
			}
		},
		"ok/mixed-ipv4-and-ipv6": func(t *testing.T) test {
			nbf := time.Now().UTC().Add(time.Minute)
			naf := time.Now().UTC().Add(5 * time.Minute)
			return test{
				nor: &NewOrderRequest{
					Identifiers: []acme.Identifier{
						{Type: "ip", Value: "192.168.42.42"},
						{Type: "ip", Value: "2001:db8::1"},
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
					var ae *acme.Error
					if assert.True(t, errors.As(err, &ae)) {
						assert.HasPrefix(t, ae.Error(), tc.err.Error())
						assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
						assert.Equals(t, ae.Type, tc.err.Type)
					}
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
		"ok/padding": func(t *testing.T) test {
			return test{
				fr: &FinalizeRequest{
					CSR: base64.RawURLEncoding.EncodeToString(csr.Raw) + "==", // add intentional padding
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := tc.fr.Validate(); err != nil {
				if assert.NotNil(t, err) {
					var ae *acme.Error
					if assert.True(t, errors.As(err, &ae)) {
						assert.HasPrefix(t, ae.Error(), tc.err.Error())
						assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
						assert.Equals(t, ae.Type, tc.err.Type)
					}
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
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

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
			fmt.Sprintf("%s/acme/%s/authz/foo", baseURL.String(), escProvName),
			fmt.Sprintf("%s/acme/%s/authz/bar", baseURL.String(), escProvName),
			fmt.Sprintf("%s/acme/%s/authz/baz", baseURL.String(), escProvName),
		},
		FinalizeURL: fmt.Sprintf("%s/acme/%s/order/orderID/finalize", baseURL.String(), escProvName),
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", o.ID)
	u := fmt.Sprintf("%s/acme/%s/order/%s",
		baseURL.String(), escProvName, o.ID)

	type test struct {
		db         acme.DB
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        acme.NewProvisionerContext(context.Background(), prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), nil)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/db.GetOrder-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							AccountID:     "accountID",
							ProvisionerID: fmt.Sprintf("acme/%s", prov.GetName()),
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							ID:               "orderID",
							AccountID:        "accountID",
							ProvisionerID:    fmt.Sprintf("acme/%s", prov.GetName()),
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
			ctx := newBaseContext(tc.ctx, tc.db, acme.NewLinker("test.ca.smallstep.com", "acme"))
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			GetOrder(w, req)
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
				expB, err := json.Marshal(o)
				assert.FatalError(t, err)

				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{u})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_newAuthorization(t *testing.T) {
	defaultProvisioner := newProv()
	type test struct {
		az   *acme.Authorization
		prov acme.Provisioner
		db   acme.DB
		err  *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/error-db.CreateChallenge": func(t *testing.T) test {
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "zap.internal",
				},
			}
			return test{
				prov: defaultProvisioner,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						assert.Equals(t, ch.AccountID, az.AccountID)
						assert.Equals(t, ch.Type, acme.DNS01)
						assert.Equals(t, ch.Token, az.Token)
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, az.Identifier.Value)
						return errors.New("force")
					},
				},
				az:  az,
				err: acme.NewErrorISE("error creating challenge: force"),
			}
		},
		"fail/error-db.CreateAuthorization": func(t *testing.T) test {
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "zap.internal",
				},
				Status:    acme.StatusPending,
				ExpiresAt: clock.Now(),
			}
			count := 0
			var ch1, ch2, ch3 **acme.Challenge
			return test{
				prov: defaultProvisioner,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, az.AccountID)
						assert.Equals(t, ch.Token, az.Token)
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, az.Identifier.Value)
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, _az *acme.Authorization) error {
						assert.Equals(t, _az.AccountID, az.AccountID)
						assert.Equals(t, _az.Token, az.Token)
						assert.Equals(t, _az.Status, acme.StatusPending)
						assert.Equals(t, _az.Identifier, az.Identifier)
						assert.Equals(t, _az.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, _az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, _az.Wildcard, false)
						return errors.New("force")
					},
				},
				az:  az,
				err: acme.NewErrorISE("error creating authorization: force"),
			}
		},
		"ok/no-wildcard": func(t *testing.T) test {
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "zap.internal",
				},
				Status:    acme.StatusPending,
				ExpiresAt: clock.Now(),
			}
			count := 0
			var ch1, ch2, ch3 **acme.Challenge
			return test{
				prov: defaultProvisioner,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, az.AccountID)
						assert.Equals(t, ch.Token, az.Token)
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, az.Identifier.Value)
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, _az *acme.Authorization) error {
						assert.Equals(t, _az.AccountID, az.AccountID)
						assert.Equals(t, _az.Token, az.Token)
						assert.Equals(t, _az.Status, acme.StatusPending)
						assert.Equals(t, _az.Identifier, az.Identifier)
						assert.Equals(t, _az.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, _az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, _az.Wildcard, false)
						return nil
					},
				},
				az: az,
			}
		},
		"ok/wildcard": func(t *testing.T) test {
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "*.zap.internal",
				},
				Status:    acme.StatusPending,
				ExpiresAt: clock.Now(),
			}
			var ch1 **acme.Challenge
			return test{
				prov: defaultProvisioner,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						ch.ID = "dns"
						assert.Equals(t, ch.Type, acme.DNS01)
						assert.Equals(t, ch.AccountID, az.AccountID)
						assert.Equals(t, ch.Token, az.Token)
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						ch1 = &ch
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, _az *acme.Authorization) error {
						assert.Equals(t, _az.AccountID, az.AccountID)
						assert.Equals(t, _az.Token, az.Token)
						assert.Equals(t, _az.Status, acme.StatusPending)
						assert.Equals(t, _az.Identifier, acme.Identifier{
							Type:  "dns",
							Value: "zap.internal",
						})
						assert.Equals(t, _az.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, _az.Challenges, []*acme.Challenge{*ch1})
						assert.Equals(t, _az.Wildcard, true)
						return nil
					},
				},
				az: az,
			}
		},
		"ok/permanent-identifier-disabled": func(t *testing.T) test {
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "permanent-identifier",
					Value: "7b53aa19-26f7-4fac-824f-7a781de0dab0",
				},
				Status:    acme.StatusPending,
				ExpiresAt: clock.Now(),
			}
			return test{
				prov: defaultProvisioner,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						t.Errorf("createChallenge should not be called")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, _az *acme.Authorization) error {
						assert.Equals(t, _az.AccountID, az.AccountID)
						assert.Equals(t, _az.Token, az.Token)
						assert.Equals(t, _az.Status, acme.StatusPending)
						assert.Equals(t, _az.Identifier, az.Identifier)
						assert.Equals(t, _az.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, _az.Challenges, []*acme.Challenge{})
						assert.Equals(t, _az.Wildcard, false)
						return nil
					},
				},
				az: az,
			}
		},
		"ok/permanent-identifier-enabled": func(t *testing.T) test {
			var ch1 *acme.Challenge
			az := &acme.Authorization{
				AccountID: "accID",
				Identifier: acme.Identifier{
					Type:  "permanent-identifier",
					Value: "7b53aa19-26f7-4fac-824f-7a781de0dab0",
				},
				Status:    acme.StatusPending,
				ExpiresAt: clock.Now(),
			}
			deviceAttestProv := newProv()
			deviceAttestProv.(*provisioner.ACME).Challenges = []provisioner.ACMEChallenge{provisioner.DEVICE_ATTEST_01}
			return test{
				prov: deviceAttestProv,
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						ch.ID = "997bacc2-c175-4214-a3b4-a229ada5f671"
						assert.Equals(t, ch.Type, acme.DEVICEATTEST01)
						assert.Equals(t, ch.AccountID, az.AccountID)
						assert.Equals(t, ch.Token, az.Token)
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "7b53aa19-26f7-4fac-824f-7a781de0dab0")
						ch1 = ch
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, _az *acme.Authorization) error {
						assert.Equals(t, _az.AccountID, az.AccountID)
						assert.Equals(t, _az.Token, az.Token)
						assert.Equals(t, _az.Status, acme.StatusPending)
						assert.Equals(t, _az.Identifier, az.Identifier)
						assert.Equals(t, _az.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, _az.Challenges, []*acme.Challenge{ch1})
						assert.Equals(t, _az.Wildcard, false)
						return nil
					},
				},
				az: az,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if name == "ok/permanent-identifier-enabled" {
				println(1)
			}
			tc := run(t)
			ctx := newBaseContext(context.Background(), tc.db)
			ctx = acme.NewProvisionerContext(ctx, tc.prov)
			if err := newAuthorization(ctx, tc.az); err != nil {
				if assert.NotNil(t, tc.err) {
					var k *acme.Error
					if assert.True(t, errors.As(err, &k)) {
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					} else {
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})

	}
}

func TestHandler_NewOrder(t *testing.T) {
	// Request with chi context
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	u := fmt.Sprintf("%s/acme/%s/order/ordID",
		baseURL.String(), escProvName)

	type test struct {
		ca         acme.CertificateAuthority
		db         acme.DB
		ctx        context.Context
		nor        *NewOrderRequest
		statusCode int
		vr         func(t *testing.T, o *acme.Order)
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        acme.NewProvisionerContext(context.Background(), prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "failed to unmarshal new-order request payload: unexpected end of JSON input"),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "identifiers list cannot be empty"),
			}
		},
		"fail/acmeProvisionerFromContext-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), &acme.MockProvisioner{})
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 500,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, errors.New("force")
					},
				},
				err: acme.NewErrorISE("error retrieving external account binding key: force"),
			}
		},
		"fail/db.GetExternalAccountKeyByAccountID-error": func(t *testing.T) test {
			acmeProv := newACMEProv(t)
			acmeProv.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), acmeProv)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 500,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, errors.New("force")
					},
				},
				err: acme.NewErrorISE("error retrieving external account binding key: force"),
			}
		},
		"fail/newACMEPolicyEngine-error": func(t *testing.T) test {
			acmeProv := newACMEProv(t)
			acmeProv.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), acmeProv)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 500,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return &acme.ExternalAccountKey{
							Policy: &acme.Policy{
								X509: acme.X509Policy{
									Allowed: acme.PolicyNames{
										DNSNames: []string{"**.local"},
									},
								},
							},
						}, nil
					},
				},
				err: acme.NewErrorISE("error creating ACME policy engine"),
			}
		},
		"fail/isIdentifierAllowed-error": func(t *testing.T) test {
			acmeProv := newACMEProv(t)
			acmeProv.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), acmeProv)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return &acme.ExternalAccountKey{
							Policy: &acme.Policy{
								X509: acme.X509Policy{
									Allowed: acme.PolicyNames{
										DNSNames: []string{"*.local"},
									},
								},
							},
						}, nil
					},
				},
				err: acme.NewError(acme.ErrorRejectedIdentifierType, "not authorized"),
			}
		},
		"fail/prov.AuthorizeOrderIdentifier-error": func(t *testing.T) test {
			options := &provisioner.Options{
				X509: &provisioner.X509Options{
					AllowedNames: &policy.X509NameOptions{
						DNSDomains: []string{"*.local"},
					},
				},
			}
			provWithPolicy := newACMEProvWithOptions(t, options)
			provWithPolicy.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), provWithPolicy)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return &acme.ExternalAccountKey{
							Policy: &acme.Policy{
								X509: acme.X509Policy{
									Allowed: acme.PolicyNames{
										DNSNames: []string{"*.internal"},
									},
								},
							},
						}, nil
					},
				},
				err: acme.NewError(acme.ErrorRejectedIdentifierType, "not authorized"),
			}
		},
		"fail/ca.AreSANsAllowed-error": func(t *testing.T) test {
			options := &provisioner.Options{
				X509: &provisioner.X509Options{
					AllowedNames: &policy.X509NameOptions{
						DNSDomains: []string{"*.internal"},
					},
				},
			}
			provWithPolicy := newACMEProvWithOptions(t, options)
			provWithPolicy.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), provWithPolicy)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 400,
				ca: &mockCA{
					MockAreSANsallowed: func(ctx context.Context, sans []string) error {
						return errors.New("force: not authorized by authority")
					},
				},
				db: &acme.MockDB{
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return &acme.ExternalAccountKey{
							Policy: &acme.Policy{
								X509: acme.X509Policy{
									Allowed: acme.PolicyNames{
										DNSNames: []string{"*.internal"},
									},
								},
							},
						}, nil
					},
				},
				err: acme.NewError(acme.ErrorRejectedIdentifierType, "not authorized"),
			}
		},
		"fail/error-h.newAuthorization": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				ctx:        ctx,
				statusCode: 500,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						assert.Equals(t, ch.AccountID, "accID")
						assert.Equals(t, ch.Type, acme.DNS01)
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return errors.New("force")
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				err: acme.NewErrorISE("error creating challenge: force"),
			}
		},
		"fail/error-db.CreateOrder": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			fr := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(fr)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 500,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, fr.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, fr.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return errors.New("force")
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				err: acme.NewErrorISE("error creating order: force"),
			}
		},
		"ok/multiple-authz": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
					{Type: "dns", Value: "*.zar.internal"},
				},
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3, ch4 **acme.Challenge
				az1ID, az2ID       *string
				chCount, azCount   = 0, 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch chCount {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							assert.Equals(t, ch.Value, "zap.internal")
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							assert.Equals(t, ch.Value, "zap.internal")
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							assert.Equals(t, ch.Value, "zap.internal")
							ch3 = &ch
						case 3:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							assert.Equals(t, ch.Value, "zar.internal")
							ch4 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						chCount++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						switch azCount {
						case 0:
							az.ID = "az1ID"
							az1ID = &az.ID
							assert.Equals(t, az.Identifier, nor.Identifiers[0])
							assert.Equals(t, az.Wildcard, false)
							assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						case 1:
							az.ID = "az2ID"
							az2ID = &az.ID
							assert.Equals(t, az.Identifier, acme.Identifier{
								Type:  acme.DNS,
								Value: "zar.internal",
							})
							assert.Equals(t, az.Wildcard, true)
							assert.Equals(t, az.Challenges, []*acme.Challenge{*ch4})
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						azCount++
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID, *az2ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					now := clock.Now()
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)
					expNbf := now.Add(-defaultOrderBackdate)
					expNaf := now.Add(prov.DefaultTLSCertDuration())

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{
						fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName),
						fmt.Sprintf("%s/acme/%s/authz/az2ID", baseURL.String(), escProvName),
					})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
		"ok/default-naf-nbf": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, nor.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					now := clock.Now()
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)
					expNbf := now.Add(-defaultOrderBackdate)
					expNaf := now.Add(prov.DefaultTLSCertDuration())

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName)})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
		"ok/nbf-no-naf": func(t *testing.T) test {
			now := clock.Now()
			expNbf := now.Add(10 * time.Minute)
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
				NotBefore: expNbf,
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, nor.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					now := clock.Now()
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)
					expNaf := expNbf.Add(prov.DefaultTLSCertDuration())

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName)})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
		"ok/naf-no-nbf": func(t *testing.T) test {
			now := clock.Now()
			expNaf := now.Add(15 * time.Minute)
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
				NotAfter: expNaf,
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, nor.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)
					expNbf := now.Add(-defaultOrderBackdate)

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName)})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
		"ok/naf-nbf": func(t *testing.T) test {
			now := clock.Now()
			expNbf := now.Add(5 * time.Minute)
			expNaf := now.Add(15 * time.Minute)
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
				NotBefore: expNbf,
				NotAfter:  expNaf,
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, nor.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName)})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
		"ok/default-naf-nbf-with-policy": func(t *testing.T) test {
			options := &provisioner.Options{
				X509: &provisioner.X509Options{
					AllowedNames: &policy.X509NameOptions{
						DNSDomains: []string{"*.internal"},
					},
				},
			}
			provWithPolicy := newACMEProvWithOptions(t, options)
			provWithPolicy.RequireEAB = true
			acc := &acme.Account{ID: "accID"}
			nor := &NewOrderRequest{
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "zap.internal"},
				},
			}
			b, err := json.Marshal(nor)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), provWithPolicy)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			var (
				ch1, ch2, ch3 **acme.Challenge
				az1ID         *string
				count         = 0
			)
			return test{
				ctx:        ctx,
				statusCode: 201,
				nor:        nor,
				ca:         &mockCA{},
				db: &acme.MockDB{
					MockCreateChallenge: func(ctx context.Context, ch *acme.Challenge) error {
						switch count {
						case 0:
							ch.ID = "dns"
							assert.Equals(t, ch.Type, acme.DNS01)
							ch1 = &ch
						case 1:
							ch.ID = "http"
							assert.Equals(t, ch.Type, acme.HTTP01)
							ch2 = &ch
						case 2:
							ch.ID = "tls"
							assert.Equals(t, ch.Type, acme.TLSALPN01)
							ch3 = &ch
						default:
							assert.FatalError(t, errors.New("test logic error"))
							return errors.New("force")
						}
						count++
						assert.Equals(t, ch.AccountID, "accID")
						assert.NotEquals(t, ch.Token, "")
						assert.Equals(t, ch.Status, acme.StatusPending)
						assert.Equals(t, ch.Value, "zap.internal")
						return nil
					},
					MockCreateAuthorization: func(ctx context.Context, az *acme.Authorization) error {
						az.ID = "az1ID"
						az1ID = &az.ID
						assert.Equals(t, az.AccountID, "accID")
						assert.NotEquals(t, az.Token, "")
						assert.Equals(t, az.Status, acme.StatusPending)
						assert.Equals(t, az.Identifier, nor.Identifiers[0])
						assert.Equals(t, az.Challenges, []*acme.Challenge{*ch1, *ch2, *ch3})
						assert.Equals(t, az.Wildcard, false)
						return nil
					},
					MockCreateOrder: func(ctx context.Context, o *acme.Order) error {
						o.ID = "ordID"
						assert.Equals(t, o.AccountID, "accID")
						assert.Equals(t, o.ProvisionerID, prov.GetID())
						assert.Equals(t, o.Status, acme.StatusPending)
						assert.Equals(t, o.Identifiers, nor.Identifiers)
						assert.Equals(t, o.AuthorizationIDs, []string{*az1ID})
						return nil
					},
					MockGetExternalAccountKeyByAccountID: func(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, prov.GetID(), provisionerID)
						assert.Equals(t, "accID", accountID)
						return nil, nil
					},
				},
				vr: func(t *testing.T, o *acme.Order) {
					now := clock.Now()
					testBufferDur := 5 * time.Second
					orderExpiry := now.Add(defaultOrderExpiry)
					expNbf := now.Add(-defaultOrderBackdate)
					expNaf := now.Add(prov.DefaultTLSCertDuration())

					assert.Equals(t, o.ID, "ordID")
					assert.Equals(t, o.Status, acme.StatusPending)
					assert.Equals(t, o.Identifiers, nor.Identifiers)
					assert.Equals(t, o.AuthorizationURLs, []string{fmt.Sprintf("%s/acme/%s/authz/az1ID", baseURL.String(), escProvName)})
					assert.True(t, o.NotBefore.Add(-testBufferDur).Before(expNbf))
					assert.True(t, o.NotBefore.Add(testBufferDur).After(expNbf))
					assert.True(t, o.NotAfter.Add(-testBufferDur).Before(expNaf))
					assert.True(t, o.NotAfter.Add(testBufferDur).After(expNaf))
					assert.True(t, o.ExpiresAt.Add(-testBufferDur).Before(orderExpiry))
					assert.True(t, o.ExpiresAt.Add(testBufferDur).After(orderExpiry))
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.ca)
			ctx := newBaseContext(tc.ctx, tc.db, acme.NewLinker("test.ca.smallstep.com", "acme"))
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			NewOrder(w, req)
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
				ro := new(acme.Order)
				assert.FatalError(t, json.Unmarshal(body, ro))
				if tc.vr != nil {
					tc.vr(t, ro)
				}

				assert.Equals(t, res.Header["Location"], []string{u})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_FinalizeOrder(t *testing.T) {
	mockMustAuthority(t, &mockCA{})
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

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
			fmt.Sprintf("%s/acme/%s/authz/foo", baseURL.String(), escProvName),
			fmt.Sprintf("%s/acme/%s/authz/bar", baseURL.String(), escProvName),
			fmt.Sprintf("%s/acme/%s/authz/baz", baseURL.String(), escProvName),
		},
		FinalizeURL:    fmt.Sprintf("%s/acme/%s/order/orderID/finalize", baseURL.String(), escProvName),
		CertificateURL: fmt.Sprintf("%s/acme/%s/certificate/certID", baseURL.String(), escProvName),
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", o.ID)
	u := fmt.Sprintf("%s/acme/%s/order/%s",
		baseURL.String(), escProvName, o.ID)

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
				db:         &acme.MockDB{},
				ctx:        acme.NewProvisionerContext(context.Background(), prov),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				db:         &acme.MockDB{},
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "unable to parse csr: asn1: syntax error: sequence truncated"),
			}
		},
		"fail/db.GetOrder-error": func(t *testing.T) test {

			acc := &acme.Account{ID: "accountID"}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							AccountID:     "accountID",
							ProvisionerID: fmt.Sprintf("acme/%s", prov.GetName()),
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db: &acme.MockDB{
					MockGetOrder: func(ctx context.Context, id string) (*acme.Order, error) {
						return &acme.Order{
							ID:               "orderID",
							AccountID:        "accountID",
							ProvisionerID:    fmt.Sprintf("acme/%s", prov.GetName()),
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
			ctx := newBaseContext(tc.ctx, tc.db, acme.NewLinker("test.ca.smallstep.com", "acme"))
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			FinalizeOrder(w, req)
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
				expB, err := json.Marshal(o)
				assert.FatalError(t, err)

				ro := new(acme.Order)
				assert.FatalError(t, json.Unmarshal(body, ro))

				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{u})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_challengeTypes(t *testing.T) {
	type args struct {
		az *acme.Authorization
	}
	tests := []struct {
		name string
		args args
		want []acme.ChallengeType
	}{
		{
			name: "ok/dns",
			args: args{
				az: &acme.Authorization{
					Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
					Wildcard:   false,
				},
			},
			want: []acme.ChallengeType{acme.DNS01, acme.HTTP01, acme.TLSALPN01},
		},
		{
			name: "ok/wildcard",
			args: args{
				az: &acme.Authorization{
					Identifier: acme.Identifier{Type: "dns", Value: "*.example.com"},
					Wildcard:   true,
				},
			},
			want: []acme.ChallengeType{acme.DNS01},
		},
		{
			name: "ok/ip",
			args: args{
				az: &acme.Authorization{
					Identifier: acme.Identifier{Type: "ip", Value: "192.168.42.42"},
					Wildcard:   false,
				},
			},
			want: []acme.ChallengeType{acme.HTTP01, acme.TLSALPN01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeTypes(tt.args.az); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Handler.challengeTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimIfWildcard(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantValue string
		wantBool  bool
	}{
		{
			name:      "no trim",
			arg:       "smallstep.com",
			wantValue: "smallstep.com",
			wantBool:  false,
		},
		{
			name:      "trim",
			arg:       "*.smallstep.com",
			wantValue: "smallstep.com",
			wantBool:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := trimIfWildcard(tt.arg)
			assert.Equals(t, v, tt.wantValue)
			assert.Equals(t, ok, tt.wantBool)
		})
	}
}
