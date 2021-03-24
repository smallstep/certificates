package acme

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/jose"
)

func TestKeyToID(t *testing.T) {
	type test struct {
		jwk *jose.JSONWebKey
		exp string
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/error-generating-thumbprint": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				jwk: jwk,
				err: NewErrorISE("error generating jwk thumbprint: square/go-jose: unknown key type 'string'"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			kid, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)

			return test{
				jwk: jwk,
				exp: base64.RawURLEncoding.EncodeToString(kid),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if id, err := KeyToID(tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, id, tc.exp)
				}
			}
		})
	}
}

func TestAccount_IsValid(t *testing.T) {
	type test struct {
		acc *Account
		exp bool
	}
	tests := map[string]test{
		"valid":   {acc: &Account{Status: StatusValid}, exp: true},
		"invalid": {acc: &Account{Status: StatusInvalid}, exp: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equals(t, tc.acc.IsValid(), tc.exp)
		})
	}
}
