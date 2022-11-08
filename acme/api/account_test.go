package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
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

type fakeProvisioner struct{}

func (*fakeProvisioner) AuthorizeOrderIdentifier(ctx context.Context, identifier provisioner.ACMEIdentifier) error {
	return nil
}

func (*fakeProvisioner) AuthorizeSign(ctx context.Context, token string) ([]provisioner.SignOption, error) {
	return nil, nil
}

func (*fakeProvisioner) IsChallengeEnabled(ctx context.Context, challenge provisioner.ACMEChallenge) bool {
	return true
}

func (*fakeProvisioner) IsAttestationFormatEnabled(ctx context.Context, format provisioner.ACMEAttestationFormat) bool {
	return true
}

func (*fakeProvisioner) GetAttestationRoots() (*x509.CertPool, bool) {
	return nil, false
}

func (*fakeProvisioner) AuthorizeRevoke(ctx context.Context, token string) error { return nil }
func (*fakeProvisioner) GetID() string                                           { return "" }
func (*fakeProvisioner) GetName() string                                         { return "" }
func (*fakeProvisioner) DefaultTLSCertDuration() time.Duration                   { return 0 }
func (*fakeProvisioner) GetOptions() *provisioner.Options                        { return nil }

func newProv() acme.Provisioner {
	// Initialize provisioners
	p := &provisioner.ACME{
		Type: "ACME",
		Name: "test@acme-<test>provisioner.com",
	}
	if err := p.Init(provisioner.Config{Claims: globalProvisionerClaims}); err != nil {
		fmt.Printf("%v", err)
	}
	return p
}

func newProvWithOptions(options *provisioner.Options) acme.Provisioner {
	// Initialize provisioners
	p := &provisioner.ACME{
		Type:    "ACME",
		Name:    "test@acme-<test>provisioner.com",
		Options: options,
	}
	if err := p.Init(provisioner.Config{Claims: globalProvisionerClaims}); err != nil {
		fmt.Printf("%v", err)
	}
	return p
}

func newACMEProv(t *testing.T) *provisioner.ACME {
	p := newProv()
	a, ok := p.(*provisioner.ACME)
	if !ok {
		t.Fatal("not a valid ACME provisioner")
	}
	return a
}

func newACMEProvWithOptions(t *testing.T, options *provisioner.Options) *provisioner.ACME {
	p := newProvWithOptions(options)
	a, ok := p.(*provisioner.ACME)
	if !ok {
		t.Fatal("not a valid ACME provisioner")
	}
	return a
}

func createEABJWS(jwk *jose.JSONWebKey, hmacKey []byte, keyID, u string) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm("HS256"),
			Key:       hmacKey,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": keyID,
				"url": u,
			},
			EmbedJWK: false,
		},
	)
	if err != nil {
		return nil, err
	}

	jwkJSONBytes, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, err
	}

	jws, err := signer.Sign(jwkJSONBytes)
	if err != nil {
		return nil, err
	}

	raw, err := jws.CompactSerialize()
	if err != nil {
		return nil, err
	}

	parsedJWS, err := jose.ParseJWS(raw)
	if err != nil {
		return nil, err
	}

	return parsedJWS, nil
}

func createRawEABJWS(jwk *jose.JSONWebKey, hmacKey []byte, keyID, u string) ([]byte, error) {
	jws, err := createEABJWS(jwk, hmacKey, keyID, u)
	if err != nil {
		return nil, err
	}

	rawJWS := jws.FullSerialize()
	return []byte(rawJWS), nil
}

func TestNewAccountRequest_Validate(t *testing.T) {
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
				err: acme.NewError(acme.ErrorMalformedType, "incompatible input; onlyReturnExisting must be alone"),
			}
		},
		"fail/bad-contact": func(t *testing.T) test {
			return test{
				nar: &NewAccountRequest{
					Contact: []string{"foo", ""},
				},
				err: acme.NewError(acme.ErrorMalformedType, "contact cannot be empty string"),
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
					var ae *acme.Error
					if assert.True(t, errors.As(err, &ae)) {
						assert.HasPrefix(t, ae.Error(), tc.err.Error())
						assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
						assert.Equals(t, ae.Type, tc.err.Type)
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestUpdateAccountRequest_Validate(t *testing.T) {
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
				err: acme.NewError(acme.ErrorMalformedType, "incompatible input; "+
					"contact and status updates are mutually exclusive"),
			}
		},
		"fail/bad-contact": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Contact: []string{"foo", ""},
				},
				err: acme.NewError(acme.ErrorMalformedType, "contact cannot be empty string"),
			}
		},
		"fail/bad-status": func(t *testing.T) test {
			return test{
				uar: &UpdateAccountRequest{
					Status: "foo",
				},
				err: acme.NewError(acme.ErrorMalformedType, "cannot update account "+
					"status to foo, only deactivated"),
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
					var ae *acme.Error
					if assert.True(t, errors.As(err, &ae)) {
						assert.HasPrefix(t, ae.Error(), tc.err.Error())
						assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
						assert.Equals(t, ae.Type, tc.err.Type)
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestHandler_GetOrdersByAccountID(t *testing.T) {
	accID := "account-id"

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("accID", accID)

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	u := fmt.Sprintf("http://ca.smallstep.com/acme/%s/account/%s/orders", provName, accID)

	oids := []string{"foo", "bar"}
	oidURLs := []string{
		fmt.Sprintf("%s/acme/%s/order/foo", baseURL.String(), provName),
		fmt.Sprintf("%s/acme/%s/order/bar", baseURL.String(), provName),
	}

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
				ctx:        context.Background(),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.WithValue(context.Background(), accContextKey, nil),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/account-id-mismatch": func(t *testing.T) test {
			acc := &acme.Account{ID: "foo"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 401,
				err:        acme.NewError(acme.ErrorUnauthorizedType, "account ID does not match url param"),
			}
		},
		"fail/db.GetOrdersByAccountID-error": func(t *testing.T) test {
			acc := &acme.Account{ID: accID}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
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
			acc := &acme.Account{ID: accID}
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				db: &acme.MockDB{
					MockGetOrdersByAccountID: func(ctx context.Context, id string) ([]string, error) {
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
			ctx := acme.NewContext(tc.ctx, tc.db, nil, acme.NewLinker("test.ca.smallstep.com", "acme"), nil)
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			GetOrdersByAccountID(w, req)
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
				expB, err := json.Marshal(oidURLs)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_NewAccount(t *testing.T) {
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	provID := prov.GetID()

	type test struct {
		db         acme.DB
		acc        *acme.Account
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-payload": func(t *testing.T) test {
			return test{
				db:         &acme.MockDB{},
				ctx:        context.Background(),
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), payloadContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err: acme.NewError(acme.ErrorMalformedType, "failed to "+
					"unmarshal new-account request payload: unexpected end of JSON input"),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", ""},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "contact cannot be empty string"),
			}
		},
		"fail/no-existing-account": func(t *testing.T) test {
			nar := &NewAccountRequest{
				OnlyReturnExisting: true,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-jwk": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jwk expected in request context"),
			}
		},
		"fail/nil-jwk": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jwk expected in request context"),
			}
		},
		"fail/new-account-no-eab-provided": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: nil,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			prov := newACMEProv(t)
			prov.RequireEAB = true
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorExternalAccountRequiredType, "no external account binding provided"),
			}
		},
		"fail/db.CreateAccount-error": func(t *testing.T) test {
			nar := &NewAccountRequest{
				Contact: []string{"foo", "bar"},
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			return test{
				db: &acme.MockDB{
					MockCreateAccount: func(ctx context.Context, acc *acme.Account) error {
						assert.Equals(t, acc.Contact, nar.Contact)
						assert.Equals(t, acc.Key, jwk)
						return acme.NewErrorISE("force")
					},
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"fail/acmeProvisionerFromContext": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, &fakeProvisioner{})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewError(acme.ErrorServerInternalType, "provisioner in context is not an ACME provisioner"),
			}
		},
		"fail/db.UpdateExternalAccountKey-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			payloadBytes, err := json.Marshal(nar)
			assert.FatalError(t, err)
			so := new(jose.SignerOptions)
			so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
			so.WithHeader("url", url)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign(payloadBytes)
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			parsedJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			prov := newACMEProv(t)
			prov.RequireEAB = true
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			eak := &acme.ExternalAccountKey{
				ID:            "eakID",
				ProvisionerID: provID,
				Reference:     "testeak",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Now(),
			}
			return test{
				db: &acme.MockDB{
					MockCreateAccount: func(ctx context.Context, acc *acme.Account) error {
						acc.ID = "accountID"
						assert.Equals(t, acc.Contact, nar.Contact)
						assert.Equals(t, acc.Key, jwk)
						return nil
					},
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return eak, nil
					},
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerName string, eak *acme.ExternalAccountKey) error {
						return errors.New("force")
					},
				},
				acc: &acme.Account{
					ID:                     "accountID",
					Key:                    jwk,
					Status:                 acme.StatusValid,
					Contact:                []string{"foo", "bar"},
					OrdersURL:              fmt.Sprintf("%s/acme/%s/account/accountID/orders", baseURL.String(), escProvName),
					ExternalAccountBinding: eab,
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewError(acme.ErrorServerInternalType, "error updating external account binding key"),
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
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db: &acme.MockDB{
					MockCreateAccount: func(ctx context.Context, acc *acme.Account) error {
						acc.ID = "accountID"
						assert.Equals(t, acc.Contact, nar.Contact)
						assert.Equals(t, acc.Key, jwk)
						return nil
					},
				},
				acc: &acme.Account{
					ID:        "accountID",
					Key:       jwk,
					Status:    acme.StatusValid,
					Contact:   []string{"foo", "bar"},
					OrdersURL: fmt.Sprintf("%s/acme/%s/account/accountID/orders", baseURL.String(), escProvName),
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
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{
				ID:      "accountID",
				Key:     jwk,
				Status:  acme.StatusValid,
				Contact: []string{"foo", "bar"},
			}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, accContextKey, acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				acc:        acc,
				statusCode: 200,
			}
		},
		"ok/new-account-no-eab-required": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			b, err := json.Marshal(nar)
			assert.FatalError(t, err)
			prov := newACMEProv(t)
			prov.RequireEAB = false
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db: &acme.MockDB{
					MockCreateAccount: func(ctx context.Context, acc *acme.Account) error {
						acc.ID = "accountID"
						assert.Equals(t, acc.Contact, nar.Contact)
						assert.Equals(t, acc.Key, jwk)
						return nil
					},
				},
				acc: &acme.Account{
					ID:        "accountID",
					Key:       jwk,
					Status:    acme.StatusValid,
					Contact:   []string{"foo", "bar"},
					OrdersURL: fmt.Sprintf("%s/acme/%s/account/accountID/orders", baseURL.String(), escProvName),
				},
				ctx:        ctx,
				statusCode: 201,
			}
		},
		"ok/new-account-with-eab": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			payloadBytes, err := json.Marshal(nar)
			assert.FatalError(t, err)
			so := new(jose.SignerOptions)
			so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
			so.WithHeader("url", url)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign(payloadBytes)
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			parsedJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			prov := newACMEProv(t)
			prov.RequireEAB = true
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockCreateAccount: func(ctx context.Context, acc *acme.Account) error {
						acc.ID = "accountID"
						assert.Equals(t, acc.Contact, nar.Contact)
						assert.Equals(t, acc.Key, jwk)
						return nil
					},
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     time.Now(),
						}, nil
					},
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerName string, eak *acme.ExternalAccountKey) error {
						return nil
					},
				},
				acc: &acme.Account{
					ID:                     "accountID",
					Key:                    jwk,
					Status:                 acme.StatusValid,
					Contact:                []string{"foo", "bar"},
					OrdersURL:              fmt.Sprintf("%s/acme/%s/account/accountID/orders", baseURL.String(), escProvName),
					ExternalAccountBinding: eab,
				},
				ctx:        ctx,
				statusCode: 201,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewContext(tc.ctx, tc.db, nil, acme.NewLinker("test.ca.smallstep.com", "acme"), nil)
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			NewAccount(w, req)
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
				expB, err := json.Marshal(tc.acc)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/account/%s", baseURL.String(),
						escProvName, "accountID")})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}

func TestHandler_GetOrUpdateAccount(t *testing.T) {
	accID := "accountID"
	acc := acme.Account{
		ID:        accID,
		Status:    "valid",
		OrdersURL: fmt.Sprintf("https://ca.smallstep.com/acme/account/%s/orders", accID),
	}
	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

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
				ctx:        context.Background(),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "failed to unmarshal new-account request payload: unexpected end of JSON input"),
			}
		},
		"fail/malformed-payload-error": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Contact: []string{"foo", ""},
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorMalformedType, "contact cannot be empty string"),
			}
		},
		"fail/db.UpdateAccount-error": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Status: "deactivated",
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db: &acme.MockDB{
					MockUpdateAccount: func(ctx context.Context, upd *acme.Account) error {
						assert.Equals(t, upd.Status, acme.StatusDeactivated)
						assert.Equals(t, upd.ID, acc.ID)
						return acme.NewErrorISE("force")
					},
				},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("force"),
			}
		},
		"ok/deactivate": func(t *testing.T) test {
			uar := &UpdateAccountRequest{
				Status: "deactivated",
			}
			b, err := json.Marshal(uar)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db: &acme.MockDB{
					MockUpdateAccount: func(ctx context.Context, upd *acme.Account) error {
						assert.Equals(t, upd.Status, acme.StatusDeactivated)
						assert.Equals(t, upd.ID, acc.ID)
						return nil
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db:         &acme.MockDB{},
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
				db: &acme.MockDB{
					MockUpdateAccount: func(ctx context.Context, upd *acme.Account) error {
						assert.Equals(t, upd.Contact, uar.Contact)
						assert.Equals(t, upd.ID, acc.ID)
						return nil
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
		"ok/post-as-get": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isPostAsGet: true})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewContext(tc.ctx, tc.db, nil, acme.NewLinker("test.ca.smallstep.com", "acme"), nil)
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			GetOrUpdateAccount(w, req)
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
				expB, err := json.Marshal(acc)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"],
					[]string{fmt.Sprintf("%s/acme/%s/account/%s", baseURL.String(),
						escProvName, accID)})
				assert.Equals(t, res.Header["Content-Type"], []string{"application/json"})
			}
		})
	}
}
