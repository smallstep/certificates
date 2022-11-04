package authority

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
)

var testAudiences = provisioner.Audiences{
	Sign:      []string{"https://example.com/1.0/sign", "https://example.com/sign"},
	Revoke:    []string{"https://example.com/1.0/revoke", "https://example.com/revoke"},
	SSHSign:   []string{"https://example.com/1.0/ssh/sign"},
	SSHRevoke: []string{"https://example.com/1.0/ssh/revoke"},
	SSHRenew:  []string{"https://example.com/1.0/ssh/renew"},
	SSHRekey:  []string{"https://example.com/1.0/ssh/rekey"},
}

type tokOption func(*jose.SignerOptions) error

func withSSHPOPFile(cert *ssh.Certificate) tokOption {
	return func(so *jose.SignerOptions) error {
		so.WithHeader("sshpop", base64.StdEncoding.EncodeToString(cert.Marshal()))
		return nil
	}
}

func generateToken(sub, iss, aud string, sans []string, iat time.Time, jwk *jose.JSONWebKey, tokOpts ...tokOption) (string, error) {
	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", jwk.KeyID)

	for _, o := range tokOpts {
		if err := o(so); err != nil {
			return "", err
		}
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key}, so)
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

func TestAuthority_authorizeToken(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://example.com/revoke"}

	type authorizeTest struct {
		auth  *Authority
		token string
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/prehistoric-token": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				IssuedAt:  jose.NewNumericDate(now.Add(-time.Hour)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("token issued before the bootstrap of certificate authority"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/provisioner-not-found": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			raw, err := jose.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("provisioner not found or invalid audience (https://example.com/revoke)"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/simpledb": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
		"fail/simpledb/token-already-used": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = _a.authorizeToken(context.Background(), raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  _a,
				token: raw,
				err:   errors.New("token already used"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/sha256": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
		"fail/sha256/token-already-used": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = _a.authorizeToken(context.Background(), raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  _a,
				token: raw,
				err:   errors.New("token already used"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/mockNoSQLDB": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
			}

			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  _a,
				token: raw,
			}
		},
		"fail/mockNoSQLDB/error": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return false, errors.New("force")
				},
			}

			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  _a,
				token: raw,
				err:   errors.New("failed when attempting to store token: force"),
				code:  http.StatusInternalServerError,
			}
		},
		"fail/mockNoSQLDB/token-already-used": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return false, nil
				},
			}

			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  _a,
				token: raw,
				err:   errors.New("token already used"),
				code:  http.StatusUnauthorized,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			p, err := tc.auth.authorizeToken(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, p.GetID(), "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				}
			}
		})
	}
}

func TestAuthority_authorizeRevoke(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://example.com/revoke"}

	type authorizeTest struct {
		auth  *Authority
		token string
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/token/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeRevoke: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/token/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeRevoke: jwk.AuthorizeRevoke: jwk.authorizeToken; jwk token subject cannot be empty"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/token": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			if err := tc.auth.authorizeRevoke(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthority_authorizeSign(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://example.com/sign"}

	type authorizeTest struct {
		auth  *Authority
		token string
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeSign: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeSign: jwk.AuthorizeSign: jwk.authorizeToken; jwk token subject cannot be empty"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			got, err := tc.auth.authorizeSign(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, 10, len(got)) // number of provisioner.SignOptions returned
				}
			}
		})
	}
}

func TestAuthority_Authorize(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()
	validIssuer := "step-cli"

	type authorizeTest struct {
		auth  *Authority
		token string
		ctx   context.Context
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"default-to-signMethod": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   context.Background(),
				err:   errors.New("authority.Authorize: authority.authorizeSign: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sign/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSign: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/sign": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.Sign,
				ID:        "1",
			}
			token, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: token,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod),
			}
		},
		"fail/revoke/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod),
				err:   errors.New("authority.Authorize: authority.authorizeRevoke: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/revoke": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.Revoke,
				ID:        "2",
			}
			token, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: token,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod),
			}
		},
		"fail/sshSign/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHSignMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSSHSign: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sshSign/disabled": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.sshCAHostCertSignKey = nil
			_a.sshCAUserCertSignKey = nil
			return &authorizeTest{
				auth:  _a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHSignMethod),
				err:   errors.New("authority.Authorize; ssh certificate flows are not enabled"),
				code:  http.StatusNotImplemented,
			}
		},
		"ok/sshSign": func(t *testing.T) *authorizeTest {
			raw, err := generateSimpleSSHUserToken(validIssuer, testAudiences.SSHSign[0], jwk)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHSignMethod),
			}
		},
		"fail/sshRenew/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRenewMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSSHRenew: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sshRenew/disabled": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.sshCAHostCertSignKey = nil
			_a.sshCAUserCertSignKey = nil
			return &authorizeTest{
				auth:  _a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRenewMethod),
				err:   errors.New("authority.Authorize; ssh certificate flows are not enabled"),
				code:  http.StatusNotImplemented,
			}
		},
		"ok/sshRenew": func(t *testing.T) *authorizeTest {
			key, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
			assert.FatalError(t, err)
			signer, ok := key.(crypto.Signer)
			assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
			sshSigner, err := ssh.NewSignerFromSigner(signer)
			assert.FatalError(t, err)

			cert, _jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)

			p, ok := a.provisioners.Load("sshpop/sshpop")
			assert.Fatal(t, ok, "sshpop provisioner not found in test authority")

			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRenew[0]+"#sshpop/sshpop",
				[]string{"foo.smallstep.com"}, now, _jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: tok,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRenewMethod),
			}
		},
		"fail/sshRevoke/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRevokeMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSSHRevoke: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/sshRevoke": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.SSHRevoke,
				ID:        "3",
			}
			token, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: token,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRevokeMethod),
			}
		},
		"fail/sshRekey/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRekeyMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSSHRekey: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sshRekey/disabled": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.sshCAHostCertSignKey = nil
			_a.sshCAUserCertSignKey = nil
			return &authorizeTest{
				auth:  _a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRekeyMethod),
				err:   errors.New("authority.Authorize; ssh certificate flows are not enabled"),
				code:  http.StatusNotImplemented,
			}
		},
		"ok/sshRekey": func(t *testing.T) *authorizeTest {
			key, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
			assert.FatalError(t, err)
			signer, ok := key.(crypto.Signer)
			assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
			sshSigner, err := ssh.NewSignerFromSigner(signer)
			assert.FatalError(t, err)

			cert, _jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)

			p, ok := a.provisioners.Load("sshpop/sshpop")
			assert.Fatal(t, ok, "sshpop provisioner not found in test authority")

			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRekey[0]+"#sshpop/sshpop",
				[]string{"foo.smallstep.com"}, now, _jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)

			return &authorizeTest{
				auth:  a,
				token: tok,
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRekeyMethod),
			}
		},
		"fail/unexpected-method": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), 15),
				err:   errors.New("authority.Authorize; method 15 is not supported"),
				code:  http.StatusInternalServerError,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			got, err := tc.auth.Authorize(tc.ctx, tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					assert.Nil(t, got)
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["token"], tc.token)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthority_authorizeRenew(t *testing.T) {
	fooCrt, err := pemutil.ReadCertificate("testdata/certs/foo.crt")
	fooCrt.NotAfter = time.Now().Add(time.Hour)
	assert.FatalError(t, err)

	renewDisabledCrt, err := pemutil.ReadCertificate("testdata/certs/renew-disabled.crt")
	assert.FatalError(t, err)

	otherCrt, err := pemutil.ReadCertificate("testdata/certs/provisioner-not-found.crt")
	assert.FatalError(t, err)

	type authorizeTest struct {
		auth *Authority
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/db.IsRevoked-error": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, errors.New("force")
				},
			}

			return &authorizeTest{
				auth: a,
				cert: fooCrt,
				err:  errors.New("authority.authorizeRenew: force"),
				code: http.StatusInternalServerError,
			}
		},
		"fail/revoked": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return true, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: fooCrt,
				err:  errors.New("authority.authorizeRenew: certificate has been revoked"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/load-provisioner": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: otherCrt,
				err:  errors.New("authority.authorizeRenew: provisioner not found"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/provisioner-authorize-renewal-fail": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}

			return &authorizeTest{
				auth: a,
				cert: renewDisabledCrt,
				err:  errors.New("authority.authorizeRenew: renew is disabled for provisioner 'renew_disabled'"),
				code: http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: fooCrt,
			}
		},
		"ok/from db": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
				MGetCertificateData: func(serialNumber string) (*db.CertificateData, error) {
					p, ok := a.provisioners.LoadByName("step-cli")
					if !ok {
						t.Fatal("provisioner step-cli not found")
					}
					return &db.CertificateData{
						Provisioner: &db.ProvisionerData{
							ID: p.GetID(),
						},
					}, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: fooCrt,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			err := tc.auth.authorizeRenew(context.Background(), tc.cert)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.cert.SerialNumber.String())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func generateSimpleSSHUserToken(iss, aud string, jwk *jose.JSONWebKey) (string, error) {
	return generateSSHToken("subject@localhost", iss, aud, time.Now(), &provisioner.SignSSHOptions{
		CertType:   "user",
		Principals: []string{"name"},
	}, jwk)
}

type stepPayload struct {
	SSH *provisioner.SignSSHOptions `json:"ssh,omitempty"`
}

func generateSSHToken(sub, iss, aud string, iat time.Time, sshOpts *provisioner.SignSSHOptions, jwk *jose.JSONWebKey) (string, error) {
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
		Step *stepPayload `json:"step,omitempty"`
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
		Step: &stepPayload{
			SSH: sshOpts,
		},
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}

func createSSHCert(cert *ssh.Certificate, signer ssh.Signer) (*ssh.Certificate, *jose.JSONWebKey, error) {
	now := time.Now()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "foo", 0)
	if err != nil {
		return nil, nil, err
	}
	cert.Key, err = ssh.NewPublicKey(jwk.Public().Key)
	if err != nil {
		return nil, nil, err
	}
	if cert.ValidAfter == 0 {
		cert.ValidAfter = uint64(now.Unix())
	}
	if cert.ValidBefore == 0 {
		cert.ValidBefore = uint64(now.Add(time.Hour).Unix())
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, err
	}
	return cert, jwk, nil
}

func TestAuthority_authorizeSSHSign(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://example.com/ssh/sign"}

	type authorizeTest struct {
		auth  *Authority
		token string
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeSSHSign: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeSSHSign: jwk.AuthorizeSSHSign: jwk.authorizeToken; jwk token subject cannot be empty"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			raw, err := generateSimpleSSHUserToken(validIssuer, validAudience[0], jwk)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			got, err := tc.auth.authorizeSSHSign(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 10, got) // number of provisioner.SignOptions returned
				}
			}
		})
	}
}

func TestAuthority_authorizeSSHRenew(t *testing.T) {
	now := time.Now().UTC()
	sshpop := func(a *Authority) (*ssh.Certificate, string) {
		p, ok := a.provisioners.Load("sshpop/sshpop")
		assert.Fatal(t, ok, "sshpop provisioner not found in test authority")
		key, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
		assert.FatalError(t, err)
		signer, ok := key.(crypto.Signer)
		assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
		sshSigner, err := ssh.NewSignerFromSigner(signer)
		assert.FatalError(t, err)
		cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
		assert.FatalError(t, err)
		token, err := generateToken("foo", p.GetName(), testAudiences.SSHRenew[0]+"#sshpop/sshpop", []string{"foo.smallstep.com"}, now, jwk, withSSHPOPFile(cert))
		assert.FatalError(t, err)
		return cert, token
	}

	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	validIssuer := "step-cli"

	type authorizeTest struct {
		auth  *Authority
		token string
		cert  *ssh.Certificate
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeSSHRenew: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sshRenew-unimplemented-jwk-provisioner": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.SSHRenew,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeSSHRenew: provisioner.AuthorizeSSHRenew not implemented"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/WithAuthorizeSSHRenewFunc": func(t *testing.T) *authorizeTest {
			aa := testAuthority(t, WithAuthorizeSSHRenewFunc(func(ctx context.Context, p *provisioner.Controller, cert *ssh.Certificate) error {
				return errs.Forbidden("forbidden")
			}))
			_, token := sshpop(aa)
			return &authorizeTest{
				auth:  aa,
				token: token,
				err:   errors.New("authority.authorizeSSHRenew: forbidden"),
				code:  http.StatusForbidden,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cert, token := sshpop(a)
			return &authorizeTest{
				auth:  a,
				token: token,
				cert:  cert,
			}
		},
		"ok/WithAuthorizeSSHRenewFunc": func(t *testing.T) *authorizeTest {
			aa := testAuthority(t, WithAuthorizeSSHRenewFunc(func(ctx context.Context, p *provisioner.Controller, cert *ssh.Certificate) error {
				return nil
			}))
			cert, token := sshpop(aa)
			return &authorizeTest{
				auth:  aa,
				token: token,
				cert:  cert,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			got, err := tc.auth.authorizeSSHRenew(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.Serial, got.Serial)
				}
			}
		})
	}
}

func TestAuthority_authorizeSSHRevoke(t *testing.T) {
	a := testAuthority(t, []Option{WithDatabase(&db.MockAuthDB{
		MIsSSHRevoked: func(serial string) (bool, error) {
			return false, nil
		},
		MUseToken: func(id, tok string) (bool, error) {
			return true, nil
		},
	})}...)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()
	validIssuer := "step-cli"

	type authorizeTest struct {
		auth  *Authority
		token string
		cert  *ssh.Certificate
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeSSHRevoke: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.SSHRevoke,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeSSHRevoke: jwk.AuthorizeSSHRevoke: jwk.authorizeToken; jwk token subject cannot be empty"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			key, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
			assert.FatalError(t, err)
			signer, ok := key.(crypto.Signer)
			assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
			sshSigner, err := ssh.NewSignerFromSigner(signer)
			assert.FatalError(t, err)

			cert, _jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)

			p, ok := a.provisioners.Load("sshpop/sshpop")
			assert.Fatal(t, ok, "sshpop provisioner not found in test authority")

			tok, err := generateToken(strconv.FormatUint(cert.Serial, 10), p.GetName(), testAudiences.SSHRevoke[0]+"#sshpop/sshpop",
				[]string{"foo.smallstep.com"}, now, _jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)

			return &authorizeTest{
				auth:  a,
				token: tok,
				cert:  cert,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			if err := tc.auth.authorizeSSHRevoke(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthority_authorizeSSHRekey(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"

	type authorizeTest struct {
		auth  *Authority
		token string
		cert  *ssh.Certificate
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeSSHRekey: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sshRekey-unimplemented-jwk-provisioner": func(t *testing.T) *authorizeTest {
			cl := jose.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  testAudiences.SSHRekey,
				ID:        "43",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeSSHRekey: provisioner.AuthorizeSSHRekey not implemented"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			key, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
			assert.FatalError(t, err)
			signer, ok := key.(crypto.Signer)
			assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
			sshSigner, err := ssh.NewSignerFromSigner(signer)
			assert.FatalError(t, err)

			cert, _jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)

			p, ok := a.provisioners.Load("sshpop/sshpop")
			assert.Fatal(t, ok, "sshpop provisioner not found in test authority")

			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRekey[0]+"#sshpop/sshpop",
				[]string{"foo.smallstep.com"}, now, _jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)

			return &authorizeTest{
				auth:  a,
				token: tok,
				cert:  cert,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			cert, signOpts, err := tc.auth.authorizeSSHRekey(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.Serial, cert.Serial)
					assert.Len(t, 4, signOpts)
				}
			}
		})
	}
}

func TestAuthority_AuthorizeRenewToken(t *testing.T) {
	ctx := context.Background()
	type stepProvisionerASN1 struct {
		Type          int
		Name          []byte
		CredentialID  []byte
		KeyValuePairs []string `asn1:"optional,omitempty"`
	}

	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509util.CreateCertificateRequest("test.example.com", []string{"test.example.com"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, otherSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	generateX5cToken := func(a *Authority, key crypto.Signer, claims jose.Claims, opts ...provisioner.SignOption) (string, *x509.Certificate) {
		chain, err := a.Sign(csr, provisioner.SignOptions{}, opts...)
		if err != nil {
			t.Fatal(err)
		}

		var x5c []string
		for _, c := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
		}

		so := new(jose.SignerOptions)
		so.WithType("JWT")
		so.WithHeader("x5cInsecure", x5c)
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, so)
		if err != nil {
			t.Fatal(err)
		}
		s, err := jose.Signed(sig).Claims(claims).CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return s, chain[0]
	}

	now := time.Now()
	a1 := testAuthority(t)
	t1, c1 := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	t2, c2 := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jose.NewNumericDate(now),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now.Add(-time.Hour)
		cert.NotAfter = now.Add(-time.Minute)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	t3, c3 := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	a4 := testAuthority(t)
	a4.db = &db.MockAuthDB{
		MUseToken: func(id, tok string) (bool, error) {
			return true, nil
		},
		MGetCertificateData: func(serialNumber string) (*db.CertificateData, error) {
			return &db.CertificateData{
				Provisioner: &db.ProvisionerData{ID: "Max:IMi94WBNI6gP5cNHXlZYNUzvMjGdHyBRmFoo-lCEaqk", Name: "Max"},
				RaInfo:      &provisioner.RAInfo{ProvisionerName: "ra"},
			}, nil
		},
	}
	t4, c4 := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://ra.example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badSigner, _ := generateX5cToken(a1, otherSigner, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("foobar"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badProvisioner, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("foobar"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badIssuer, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "test.example.com",
		Issuer:    "bad-issuer",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badSubject, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/renew"},
		Subject:   "bad-subject",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badNotBefore, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/sign"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now.Add(5 * time.Minute)),
		Expiry:    jose.NewNumericDate(now.Add(10 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badExpiry, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/sign"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now.Add(-5 * time.Minute)),
		Expiry:    jose.NewNumericDate(now.Add(-time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badIssuedAt, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/sign"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))
	badAudience, _ := generateX5cToken(a1, signer, jose.Claims{
		Audience:  []string{"https://example.com/1.0/sign"},
		Subject:   "test.example.com",
		Issuer:    "step-ca-client/1.0",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
	}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = now
		cert.NotAfter = now.Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{int(provisioner.TypeJWK), []byte("step-cli"), nil, nil})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1},
			Value: b,
		})
		return nil
	}))

	type args struct {
		ctx context.Context
		ott string
	}
	tests := []struct {
		name      string
		authority *Authority
		args      args
		want      *x509.Certificate
		wantErr   bool
	}{
		{"ok", a1, args{ctx, t1}, c1, false},
		{"ok expired cert", a1, args{ctx, t2}, c2, false},
		{"ok provisioner issuer", a1, args{ctx, t3}, c3, false},
		{"ok ra provisioner", a4, args{ctx, t4}, c4, false},
		{"fail token", a1, args{ctx, "not.a.token"}, nil, true},
		{"fail token reuse", a1, args{ctx, t1}, nil, true},
		{"fail token signature", a1, args{ctx, badSigner}, nil, true},
		{"fail token provisioner", a1, args{ctx, badProvisioner}, nil, true},
		{"fail token iss", a1, args{ctx, badIssuer}, nil, true},
		{"fail token sub", a1, args{ctx, badSubject}, nil, true},
		{"fail token iat", a1, args{ctx, badNotBefore}, nil, true},
		{"fail token iat", a1, args{ctx, badExpiry}, nil, true},
		{"fail token iat", a1, args{ctx, badIssuedAt}, nil, true},
		{"fail token aud", a1, args{ctx, badAudience}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.authority.AuthorizeRenewToken(tt.args.ctx, tt.args.ott)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.AuthorizeRenewToken() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.AuthorizeRenewToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
