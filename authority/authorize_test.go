package authority

import (
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/keys"
	stepJOSE "github.com/smallstep/cli/jose"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestAuthorize(t *testing.T) {
	a := testAuthority(t)
	jwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_priv.jwk",
		stepJOSE.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

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
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT"))
			assert.FatalError(t, err)
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: token KeyID cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail provisioner not found": func(t *testing.T) *authorizeTest {
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: provisioner with KeyID foo not found"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail invalid provisioner": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)

			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			_a.provisionerIDIndex.Store("foo", "42")

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: _a,
				ott:  raw,
				err: &apiError{errors.New("authorize: invalid provisioner type"),
					http.StatusInternalServerError, context{"ott": raw}},
			}
		},
		"fail invalid issuer": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "subject",
				Issuer:    "invalid-issuer",
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: invalid token"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail empty subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorize: token subject cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail verify-sig-failure": func(t *testing.T) *authorizeTest {
			_, priv2, err := keys.GenerateDefaultKeyPair()
			assert.FatalError(t, err)
			invalidKeySig, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.ES256,
				Key:       priv2,
			}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
			assert.FatalError(t, err)
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jwt.Signed(invalidKeySig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("square/go-jose: error in cryptographic primitive"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail token-already-used": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "42",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = a.Authorize(raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("token already used"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				res: []interface{}{
					"1", "2", "3",
					withIssuerAlternativeNameExtension("step-cli:" + jwk.KeyID),
					"5",
				},
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
