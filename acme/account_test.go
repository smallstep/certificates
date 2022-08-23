package acme

import (
	"crypto"
	"encoding/base64"
	"testing"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
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
					var k *Error
					if errors.As(err, &k) {
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

func TestExternalAccountKey_BindTo(t *testing.T) {
	boundAt := time.Now()
	tests := []struct {
		name string
		eak  *ExternalAccountKey
		acct *Account
		err  *Error
	}{
		{
			name: "ok",
			eak: &ExternalAccountKey{
				ID:            "eakID",
				ProvisionerID: "provID",
				Reference:     "ref",
				HmacKey:       []byte{1, 3, 3, 7},
			},
			acct: &Account{
				ID: "accountID",
			},
			err: nil,
		},
		{
			name: "fail/already-bound",
			eak: &ExternalAccountKey{
				ID:            "eakID",
				ProvisionerID: "provID",
				Reference:     "ref",
				HmacKey:       []byte{1, 3, 3, 7},
				AccountID:     "someAccountID",
				BoundAt:       boundAt,
			},
			acct: &Account{
				ID: "accountID",
			},
			err: NewError(ErrorUnauthorizedType, "external account binding key with id '%s' was already bound to account '%s' on %s", "eakID", "someAccountID", boundAt),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eak := tt.eak
			acct := tt.acct
			err := eak.BindTo(acct)
			wantErr := tt.err != nil
			gotErr := err != nil
			if wantErr != gotErr {
				t.Errorf("ExternalAccountKey.BindTo() error = %v, wantErr %v", err, tt.err)
			}
			if wantErr {
				assert.NotNil(t, err)
				var ae *Error
				if assert.True(t, errors.As(err, &ae)) {
					assert.Equals(t, ae.Type, tt.err.Type)
					assert.Equals(t, ae.Detail, tt.err.Detail)
					assert.Equals(t, ae.Identifier, tt.err.Identifier)
					assert.Equals(t, ae.Subproblems, tt.err.Subproblems)
				}
			} else {
				assert.Equals(t, eak.AccountID, acct.ID)
				assert.Equals(t, eak.HmacKey, []byte{})
				assert.NotNil(t, eak.BoundAt)
			}
		})
	}
}
