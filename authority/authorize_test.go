package authority

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"golang.org/x/crypto/ssh"
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
				err:   errors.New("authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.authorizeToken: token issued before the bootstrap of certificate authority"),
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
				err:   errors.New("authority.authorizeToken: provisioner not found or invalid audience (https://example.com/revoke)"),
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
				err:   errors.New("authority.authorizeToken: token already used"),
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
				err:   errors.New("authority.authorizeToken: token already used"),
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
				err:   errors.New("authority.authorizeToken: failed when attempting to store token: force"),
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
				err:   errors.New("authority.authorizeToken: token already used"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
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
				err:   errors.New("authority.authorizeRevoke: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
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
				err:   errors.New("authority.authorizeSign: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 7, got)
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
				err:   errors.New("authority.Authorize: authority.authorizeSign: authority.authorizeToken: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/sign/invalid-token": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				ctx:   provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod),
				err:   errors.New("authority.Authorize: authority.authorizeSign: authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.Authorize: authority.authorizeRevoke: authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.Authorize: authority.authorizeSSHSign: authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.Authorize: authority.authorizeSSHRenew: authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.Authorize: authority.authorizeSSHRevoke: authority.authorizeToken: error parsing token"),
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
				err:   errors.New("authority.Authorize: authority.authorizeSSHRekey: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
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
				err:  errors.New("authority.authorizeRenew: jwk.AuthorizeRenew; renew is disabled for jwk provisioner renew_disabled:IMi94WBNI6gP5cNHXlZYNUzvMjGdHyBRmFoo-lCEaqk"),
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
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			err := tc.auth.authorizeRenew(tc.cert)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
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
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "foo", 0)
	if err != nil {
		return nil, nil, err
	}
	cert.Key, err = ssh.NewPublicKey(jwk.Public().Key)
	if err != nil {
		return nil, nil, err
	}
	if err = cert.SignCert(rand.Reader, signer); err != nil {
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
				err:   errors.New("authority.authorizeSSHSign: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 7, got)
				}
			}
		})
	}
}

func TestAuthority_authorizeSSHRenew(t *testing.T) {
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
				err:   errors.New("authority.authorizeSSHRenew: authority.authorizeToken: error parsing token"),
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

			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRenew[0]+"#sshpop/sshpop",
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

			got, err := tc.auth.authorizeSSHRenew(context.Background(), tc.token)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
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
				err:   errors.New("authority.authorizeSSHRevoke: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
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
				err:   errors.New("authority.authorizeSSHRekey: authority.authorizeToken: error parsing token"),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.Serial, cert.Serial)
					assert.Len(t, 3, signOpts)
				}
			}
		})
	}
}
