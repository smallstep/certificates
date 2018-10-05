package authority

import (
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/ca-component/api"
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

	type authorizeTest struct {
		ott    string
		err    *apiError
		claims []api.Claim
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"invalid-ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				ott: "foo",
				err: &apiError{errors.New("error parsing OTT"),
					http.StatusUnauthorized, context{"ott": "foo"}},
				claims: nil}
		},
		"invalid-issuer": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "subject",
				Issuer:    "invalid-issuer",
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validTokenAudience,
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				ott: raw,
				err: &apiError{errors.New("error validating OTT"),
					http.StatusUnauthorized, context{"ott": raw}},
				claims: nil}
		},
		"empty-subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validTokenAudience,
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				ott: raw,
				err: &apiError{errors.New("OTT sub cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
				claims: nil}
		},
		"verify-sig-failure": func(t *testing.T) *authorizeTest {
			_, priv2, err := keys.GenerateDefaultKeyPair()
			assert.FatalError(t, err)
			invalidKeySig, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.ES256,
				Key:       priv2,
			}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
			assert.FatalError(t, err)
			cl := jwt.Claims{
				Subject:   "foo",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validTokenAudience,
			}
			raw, err := jwt.Signed(invalidKeySig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				ott: raw,
				err: &apiError{errors.New("square/go-jose: error in cryptographic primitive"),
					http.StatusUnauthorized, context{"ott": raw}},
				claims: nil}
		},
		"token-already-used": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "foo",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validTokenAudience,
				ID:        "42",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = a.Authorize(raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				ott: raw,
				err: &apiError{errors.New("token already used"),
					http.StatusUnauthorized, context{"ott": raw}},
				claims: nil}
		},
		"success": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "foo",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validTokenAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				ott:    raw,
				claims: []api.Claim{&commonNameClaim{"foo"}, &dnsNamesClaim{"foo"}, &ipAddressesClaim{"foo"}},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			assert.FatalError(t, err)

			claims, err := a.Authorize(tc.ott)
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
					assert.Equals(t, claims, tc.claims)
				}
			}
		})
	}
}
