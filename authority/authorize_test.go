package authority

import (
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
)

func generateToken(sub, iss, aud string, sans []string, iat time.Time, jwk *jose.JSONWebKey) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", err
	}

	id, err := randutil.ASCII(64)
	if err != nil {
		return "", err
	}

	claims := struct {
		jose.Claims
		SANS []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		SANS: sans,
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}

func TestAuthorize(t *testing.T) {
	a := testAuthority(t)

	key, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	// Invalid keys
	keyNoKid := &jose.JSONWebKey{Key: key.Key, KeyID: ""}
	keyBadKid := &jose.JSONWebKey{Key: key.Key, KeyID: "foo"}

	now := time.Now()
	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/sign"}

	type authorizeTest struct {
		auth *Authority
		ott  string
		err  *apiError
		res  []interface{}
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail invalid ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth: a,
				ott:  "foo",
				err: &apiError{errors.New("authorize: error parsing token"),
					http.StatusUnauthorized, context{"ott": "foo"}},
			}
		},
		"fail empty key id": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", validIssuer, validAudience[0], nil, now, keyNoKid)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: provisioner not found or invalid audience"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail provisioner not found": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", validIssuer, validAudience[0], nil, now, keyBadKid)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: provisioner not found or invalid audience"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail invalid issuer": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", "invalid-issuer", validAudience[0], nil, now, key)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: provisioner not found or invalid audience"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail empty subject": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("", validIssuer, validAudience[0], nil, now, key)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: token subject cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail verify-sig-failure": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", validIssuer, validAudience[0], nil, now, key)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw + "00",
				err: &apiError{errors.New("authorize: error parsing claims: square/go-jose: error in cryptographic primitive"),
					http.StatusUnauthorized, context{"ott": raw + "00"}},
			}
		},
		"fail token-already-used": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", validIssuer, validAudience[0], nil, now, key)
			assert.FatalError(t, err)
			_, err = a.Authorize(raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: token already used"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			raw, err := generateToken("test.smallstep.com", validIssuer, validAudience[0], nil, now, key)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				res:  []interface{}{"1", "2", "3", "4", "5", "6"},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			assert.FatalError(t, err)

			crtOpts, err := tc.auth.Authorize(tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, len(crtOpts), len(tc.res))
				}
			}
		})
	}
}
