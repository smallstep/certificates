package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func newACMEProv(t *testing.T) *provisioner.ACME {
	p := newProv()
	a, ok := p.(*provisioner.ACME)
	if !ok {
		t.Fatal("not a valid ACME provisioner")
	}
	return a
}

func createEABJWS(jwk *jose.JSONWebKey, hmacKey []byte, keyID string, url string) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm("HS256"),
			Key:       hmacKey,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": keyID,
				"url": url,
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

func createRawEABJWS(jwk *jose.JSONWebKey, hmacKey []byte, keyID string, url string) ([]byte, error) {
	jws, err := createEABJWS(jwk, hmacKey, keyID, url)
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
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
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
			h := &Handler{db: tc.db, linker: NewLinker("dns", "acme")}
			req := httptest.NewRequest("GET", u, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetOrdersByAccountID(w, req)
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
				ctx:        context.Background(),
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{})
			return test{
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
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			return test{
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			return test{
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, nil)
			return test{
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
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			return test{
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
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
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
			scepProvisioner := &provisioner.SCEP{
				Type: "SCEP",
				Name: "test@scep-<test>provisioner.com",
			}
			if err := scepProvisioner.Init(provisioner.Config{Claims: globalProvisionerClaims}); err != nil {
				assert.FatalError(t, err)
			}
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, scepProvisioner)
			return test{
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
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			eak := &acme.ExternalAccountKey{
				ID:          "eakID",
				Provisioner: escProvName,
				Reference:   "testeak",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   time.Now(),
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
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
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
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
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
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
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
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 3, 3, 7},
							CreatedAt:   time.Now(),
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
			h := &Handler{db: tc.db, linker: NewLinker("dns", "acme")}
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.NewAccount(w, req)
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
				ctx:        context.Background(),
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload expected in request context"),
			}
		},
		"fail/unmarshal-payload-error": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
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
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, &acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isPostAsGet: true})
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			return test{
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{db: tc.db, linker: NewLinker("dns", "acme")}
			req := httptest.NewRequest("GET", "/foo/bar", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetOrUpdateAccount(w, req)
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

func Test_keysAreEqual(t *testing.T) {
	jwkX, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	jwkY, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	wrongJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	wrongJWK.Key = struct{}{}
	type args struct {
		x *jose.JSONWebKey
		y *jose.JSONWebKey
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ok/nil",
			args: args{
				x: jwkX,
				y: nil,
			},
			want: false,
		},
		{
			name: "ok/equal",
			args: args{
				x: jwkX,
				y: jwkX,
			},
			want: true,
		},
		{
			name: "ok/not-equal",
			args: args{
				x: jwkX,
				y: jwkY,
			},
			want: false,
		},
		{
			name: "ok/wrong-key-type",
			args: args{
				x: wrongJWK,
				y: jwkY,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keysAreEqual(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("keysAreEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_validateExternalAccountBinding(t *testing.T) {
	acmeProv := newACMEProv(t)
	escProvName := url.PathEscape(acmeProv.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	type test struct {
		db  acme.DB
		ctx context.Context
		nar *NewAccountRequest
		eak *acme.ExternalAccountKey
		err *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok/no-eab-required-but-provided": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			prov := newACMEProv(t)
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			return test{
				db:  &acme.MockDB{},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: nil,
			}
		},
		"ok/eab": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			createdAt := time.Now()
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 3, 3, 7},
							CreatedAt:   createdAt,
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: &acme.ExternalAccountKey{
					ID:          "eakID",
					Provisioner: escProvName,
					Reference:   "testeak",
					KeyBytes:    []byte{1, 3, 3, 7},
					CreatedAt:   createdAt,
				},
				err: nil,
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
			scepProvisioner := &provisioner.SCEP{
				Type: "SCEP",
				Name: "test@scep-<test>provisioner.com",
			}
			if err := scepProvisioner.Init(provisioner.Config{Claims: globalProvisionerClaims}); err != nil {
				assert.FatalError(t, err)
			}
			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, scepProvisioner)
			return test{
				ctx: ctx,
				err: acme.NewError(acme.ErrorServerInternalType, "could not load ACME provisioner from context: provisioner in context is not an ACME provisioner"),
			}
		},
		"fail/parse-eab-jose": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal(rawEABJWS, &eab)
			assert.FatalError(t, err)
			eab.Payload += "{}"
			prov := newACMEProv(t)
			prov.RequireEAB = true
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			return test{
				db:  &acme.MockDB{},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewErrorISE("error parsing externalAccountBinding jws"),
			}
		},
		"fail/validate-eab-jws-no-signatures": func(t *testing.T) test {
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
			parsedJWS.Signatures = []jose.Signature{}
			prov := newACMEProv(t)
			prov.RequireEAB = true
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db:  &acme.MockDB{},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorMalformedType, "outer JWS must have one signature"),
			}
		},
		"fail/retrieve-eab-key-db-failure": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockError: errors.New("db failure"),
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewErrorISE("error retrieving external account key"),
			}
		},
		"fail/db.GetExternalAccountKey-not-found": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return nil, acme.ErrNotFound
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewErrorISE("error retrieving external account key"),
			}
		},
		"fail/db.GetExternalAccountKey-error": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return nil, errors.New("force")
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewErrorISE("error retrieving external account key"),
			}
		},
		"fail/db.GetExternalAccountKey-wrong-provisioner": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockError: acme.NewError(acme.ErrorUnauthorizedType, "name of provisioner does not match provisioner for which the EAB key was created"),
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorUnauthorizedType, "the field 'kid' references an unknown key: name of provisioner does not match provisioner for which the EAB key was created"),
			}
		},
		"fail/eab-already-bound": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			createdAt := time.Now()
			boundAt := time.Now().Add(1 * time.Second)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							CreatedAt:   createdAt,
							AccountID:   "some-account-id",
							BoundAt:     boundAt,
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorUnauthorizedType, "external account binding key with id '%s' was already bound to account '%s' on %s", "eakID", "some-account-id", boundAt),
			}
		},
		"fail/eab-verify": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 2, 3, 4},
							CreatedAt:   time.Now(),
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewErrorISE("error verifying externalAccountBinding signature"),
			}
		},
		"fail/eab-non-matching-keys": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			differentJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			rawEABJWS, err := createRawEABJWS(differentJWK, []byte{1, 3, 3, 7}, "eakID", url)
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
			ctx := context.WithValue(context.Background(), jwkContextKey, jwk)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 3, 3, 7},
							CreatedAt:   time.Now(),
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorUnauthorizedType, "keys in jws and eab payload do not match"),
			}
		},
		"fail/no-jwk": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 3, 3, 7},
							CreatedAt:   time.Now(),
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorServerInternalType, "jwk expected in request context"),
			}
		},
		"fail/nil-jwk": func(t *testing.T) test {
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
			ctx := context.WithValue(context.Background(), jwkContextKey, nil)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, provisionerContextKey, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:          "eakID",
							Provisioner: escProvName,
							Reference:   "testeak",
							KeyBytes:    []byte{1, 3, 3, 7},
							CreatedAt:   time.Now(),
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorServerInternalType, "jwk expected in request context"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{
				db: tc.db,
			}
			got, err := h.validateExternalAccountBinding(tc.ctx, tc.nar)
			wantErr := tc.err != nil
			gotErr := err != nil
			if wantErr != gotErr {
				t.Errorf("Handler.validateExternalAccountBinding() error = %v, want %v", err, tc.err)
			}
			if wantErr {
				assert.NotNil(t, err)
				assert.Type(t, &acme.Error{}, err)
				ae, _ := err.(*acme.Error)
				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Status, tc.err.Status)
				assert.HasPrefix(t, ae.Err.Error(), tc.err.Err.Error())
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
			} else {
				if got == nil {
					assert.Nil(t, tc.eak)
				} else {
					assert.NotNil(t, tc.eak)
					assert.Equals(t, got.ID, tc.eak.ID)
					assert.Equals(t, got.KeyBytes, tc.eak.KeyBytes)
					assert.Equals(t, got.Provisioner, tc.eak.Provisioner)
					assert.Equals(t, got.Reference, tc.eak.Reference)
					assert.Equals(t, got.CreatedAt, tc.eak.CreatedAt)
					assert.Equals(t, got.AccountID, tc.eak.AccountID)
					assert.Equals(t, got.BoundAt, tc.eak.BoundAt)
				}
			}
		})
	}
}

func Test_validateEABJWS(t *testing.T) {
	acmeProv := newACMEProv(t)
	escProvName := url.PathEscape(acmeProv.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	type test struct {
		ctx   context.Context
		jws   *jose.JSONWebSignature
		keyID string
		err   *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/nil-jws": func(t *testing.T) test {
			return test{
				jws: nil,
				err: acme.NewErrorISE("no JWS provided"),
			}
		},
		"fail/invalid-number-of-signatures": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eabJWS.Signatures = append(eabJWS.Signatures, jose.Signature{})
			return test{
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "JWS must have one signature"),
			}
		},
		"fail/invalid-algorithm": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eabJWS.Signatures[0].Protected.Algorithm = "HS42"
			return test{
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'alg' field set to invalid algorithm 'HS42'"),
			}
		},
		"fail/kid-not-set": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eabJWS.Signatures[0].Protected.KeyID = ""
			return test{
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'kid' field is required"),
			}
		},
		"fail/nonce-not-empty": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			eabJWS.Signatures[0].Protected.Nonce = "some-bogus-nonce"
			return test{
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'nonce' must not be present"),
			}
		},
		"fail/url-not-set": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			delete(eabJWS.Signatures[0].Protected.ExtraHeaders, "url")
			return test{
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'url' field is required"),
			}
		},
		"fail/no-outer-jws": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.TODO(), jwsContextKey, nil)
			return test{
				ctx: ctx,
				jws: eabJWS,
				err: acme.NewErrorISE("could not retrieve outer JWS from context"),
			}
		},
		"fail/outer-jws-multiple-signatures": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			rawEABJWS := eabJWS.FullSerialize()
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal([]byte(rawEABJWS), &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			payloadBytes, err := json.Marshal(nar)
			assert.FatalError(t, err)
			so := new(jose.SignerOptions)
			so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign(payloadBytes)
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			outerJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			outerJWS.Signatures = append(outerJWS.Signatures, jose.Signature{})
			ctx := context.WithValue(context.TODO(), jwsContextKey, outerJWS)
			return test{
				ctx: ctx,
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "outer JWS must have one signature"),
			}
		},
		"fail/outer-jws-no-url": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			rawEABJWS := eabJWS.FullSerialize()
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal([]byte(rawEABJWS), &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			payloadBytes, err := json.Marshal(nar)
			assert.FatalError(t, err)
			so := new(jose.SignerOptions)
			so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign(payloadBytes)
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			outerJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.TODO(), jwsContextKey, outerJWS)
			return test{
				ctx: ctx,
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'url' field must be set in outer JWS"),
			}
		},
		"fail/outer-jws-with-different-url": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			rawEABJWS := eabJWS.FullSerialize()
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal([]byte(rawEABJWS), &eab)
			assert.FatalError(t, err)
			nar := &NewAccountRequest{
				Contact:                []string{"foo", "bar"},
				ExternalAccountBinding: eab,
			}
			payloadBytes, err := json.Marshal(nar)
			assert.FatalError(t, err)
			so := new(jose.SignerOptions)
			so.WithHeader("alg", jose.SignatureAlgorithm(jwk.Algorithm))
			so.WithHeader("url", "this-is-not-the-same-url-as-in-the-eab-jws")
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk.Key,
			}, so)
			assert.FatalError(t, err)
			jws, err := signer.Sign(payloadBytes)
			assert.FatalError(t, err)
			raw, err := jws.CompactSerialize()
			assert.FatalError(t, err)
			outerJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.TODO(), jwsContextKey, outerJWS)
			return test{
				ctx: ctx,
				jws: eabJWS,
				err: acme.NewError(acme.ErrorMalformedType, "'url' field is not the same value as the outer JWS"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			url := fmt.Sprintf("%s/acme/%s/account/new-account", baseURL.String(), escProvName)
			eabJWS, err := createEABJWS(jwk, []byte{1, 3, 3, 7}, "eakID", url)
			assert.FatalError(t, err)
			rawEABJWS := eabJWS.FullSerialize()
			assert.FatalError(t, err)
			eab := &ExternalAccountBinding{}
			err = json.Unmarshal([]byte(rawEABJWS), &eab)
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
			outerJWS, err := jose.ParseJWS(raw)
			assert.FatalError(t, err)
			ctx := context.WithValue(context.TODO(), jwsContextKey, outerJWS)
			return test{
				ctx:   ctx,
				jws:   eabJWS,
				keyID: "eakID",
				err:   nil,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			keyID, err := validateEABJWS(tc.ctx, tc.jws)
			wantErr := tc.err != nil
			gotErr := err != nil
			if wantErr != gotErr {
				t.Errorf("validateEABJWS() error = %v, want %v", err, tc.err)
			}
			if wantErr {
				assert.NotNil(t, err)
				assert.Equals(t, tc.err.Type, err.Type)
				assert.Equals(t, tc.err.Status, err.Status)
				assert.HasPrefix(t, err.Err.Error(), tc.err.Err.Error())
				assert.Equals(t, tc.err.Detail, err.Detail)
				assert.Equals(t, tc.err.Identifier, err.Identifier)
				assert.Equals(t, tc.err.Subproblems, err.Subproblems)
			} else {
				assert.Nil(t, err)
				assert.Equals(t, tc.keyID, keyID)
			}
		})
	}
}
