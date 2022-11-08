package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
)

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
	provID := acmeProv.GetID()
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			createdAt := time.Now()
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     createdAt,
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: &acme.ExternalAccountKey{
					ID:            "eakID",
					ProvisionerID: provID,
					Reference:     "testeak",
					HmacKey:       []byte{1, 3, 3, 7},
					CreatedAt:     createdAt,
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

			ctx := context.WithValue(context.Background(), payloadContextKey, &payloadInfo{value: b})
			ctx = context.WithValue(ctx, jwkContextKey, jwk)
			ctx = acme.NewProvisionerContext(ctx, &fakeProvisioner{})
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
		"fail/db.GetExternalAccountKey-nil": func(t *testing.T) test {
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return nil, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorUnauthorizedType, "the field 'kid' references an unknown key"),
			}
		},
		"fail/db.GetExternalAccountKey-no-keybytes": func(t *testing.T) test {
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			createdAt := time.Now()
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							CreatedAt:     createdAt,
							AccountID:     "some-account-id",
							HmacKey:       []byte{},
						}, nil
					},
				},
				ctx: ctx,
				nar: &NewAccountRequest{
					Contact:                []string{"foo", "bar"},
					ExternalAccountBinding: eab,
				},
				eak: nil,
				err: acme.NewError(acme.ErrorServerInternalType, "external account binding key with id 'eakID' does not have secret bytes"),
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
			ctx = acme.NewProvisionerContext(ctx, prov)
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			createdAt := time.Now()
			boundAt := time.Now().Add(1 * time.Second)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							CreatedAt:     createdAt,
							AccountID:     "some-account-id",
							HmacKey:       []byte{1, 3, 3, 7},
							BoundAt:       boundAt,
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 2, 3, 4},
							CreatedAt:     time.Now(),
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     time.Now(),
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
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     time.Now(),
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
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			return test{
				db: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
						return &acme.ExternalAccountKey{
							ID:            "eakID",
							ProvisionerID: provID,
							Reference:     "testeak",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     time.Now(),
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
			ctx := acme.NewDatabaseContext(tc.ctx, tc.db)
			got, err := validateExternalAccountBinding(ctx, tc.nar)
			wantErr := tc.err != nil
			gotErr := err != nil
			if wantErr != gotErr {
				t.Errorf("Handler.validateExternalAccountBinding() error = %v, want %v", err, tc.err)
			}
			if wantErr {
				assert.NotNil(t, err)
				assert.Type(t, &acme.Error{}, err)
				var ae *acme.Error
				if assert.True(t, errors.As(err, &ae)) {
					assert.Equals(t, ae.Type, tc.err.Type)
					assert.Equals(t, ae.Status, tc.err.Status)
					assert.HasPrefix(t, ae.Err.Error(), tc.err.Err.Error())
					assert.Equals(t, ae.Detail, tc.err.Detail)
					assert.Equals(t, ae.Identifier, tc.err.Identifier)
					assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				}
			} else {
				if got == nil {
					assert.Nil(t, tc.eak)
				} else {
					assert.NotNil(t, tc.eak)
					assert.Equals(t, got.ID, tc.eak.ID)
					assert.Equals(t, got.HmacKey, tc.eak.HmacKey)
					assert.Equals(t, got.ProvisionerID, tc.eak.ProvisionerID)
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
