package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestSSHPOP_Getters(t *testing.T) {
	p, err := generateSSHPOP()
	assert.FatalError(t, err)
	id := "sshpop/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("SSHPOP.GetID() = %v, want %v", got, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("SSHPOP.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeSSHPOP {
		t.Errorf("SSHPOP.GetType() = %v, want %v", got, TypeSSHPOP)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("SSHPOP.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
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

func generateSSHPOPToken(p Interface, cert *ssh.Certificate, jwk *jose.JSONWebKey) (string, error) {
	return generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
		[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
}

func TestSSHPOP_authorizeToken(t *testing.T) {
	key, err := pemutil.Read("./testdata/secrets/ssh_user_ca_key")
	assert.FatalError(t, err)
	signer, ok := key.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	assert.FatalError(t, err)

	type test struct {
		p     *SSHPOP
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; error extracting sshpop header from token: extractSSHPOPCert; error parsing token: "),
			}
		},
		"fail/cert-not-yet-valid": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{
				CertType:   ssh.UserCert,
				ValidAfter: uint64(time.Now().Add(time.Minute).Unix()),
			}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; sshpop certificate validAfter is in the future"),
			}
		},
		"fail/cert-past-validity": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{
				CertType:    ssh.UserCert,
				ValidBefore: uint64(time.Now().Add(-time.Minute).Unix()),
			}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; sshpop certificate validBefore is in the past"),
			}
		},
		"fail/no-signer-found": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; could not find valid ca signer to verify sshpop certificate"),
			}
		},
		"fail/error-parsing-claims-bad-sig": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, _, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			otherJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, otherJWK)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; error parsing sshpop token claims"),
			}
		},
		"fail/invalid-claims-issuer": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", "bar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; invalid sshpop token"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), "invalid-aud", "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; sshpop token has invalid audience claim (aud)"),
			}
		},
		"fail/empty-subject": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.authorizeToken; sshpop token subject cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if claims, err := tc.p.authorizeToken(tc.token, testAudiences.Sign, true); err != nil {
				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tc.code)
				}
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else if assert.Nil(t, tc.err) {
				assert.NotNil(t, claims)
			}
		})
	}
}

func TestSSHPOP_AuthorizeSSHRevoke(t *testing.T) {
	key, err := pemutil.Read("./testdata/secrets/ssh_user_ca_key")
	assert.FatalError(t, err)
	signer, ok := key.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	assert.FatalError(t, err)

	type test struct {
		p     *SSHPOP
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.AuthorizeSSHRevoke: sshpop.authorizeToken; error extracting sshpop header from token: extractSSHPOPCert; error parsing token: "),
			}
		},
		"fail/subject-not-equal-serial": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRevoke[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("sshpop token subject must be equivalent to sshpop certificate serial number"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{Serial: 123455, CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", p.GetName(), testAudiences.SSHRevoke[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeSSHRevoke(context.Background(), tc.token); err != nil {
				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tc.code)
				}
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestSSHPOP_AuthorizeSSHRenew(t *testing.T) {
	key, err := pemutil.Read("./testdata/secrets/ssh_user_ca_key")
	assert.FatalError(t, err)
	userSigner, ok := key.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh user signing key to crypto signer")
	sshUserSigner, err := ssh.NewSignerFromSigner(userSigner)
	assert.FatalError(t, err)

	hostKey, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
	assert.FatalError(t, err)
	hostSigner, ok := hostKey.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh host signing key to crypto signer")
	sshHostSigner, err := ssh.NewSignerFromSigner(hostSigner)
	assert.FatalError(t, err)

	type test struct {
		p     *SSHPOP
		token string
		cert  *ssh.Certificate
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.AuthorizeSSHRenew: sshpop.authorizeToken; error extracting sshpop header from token: extractSSHPOPCert; error parsing token: "),
			}
		},
		"fail/not-host-cert": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshUserSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRenew[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("sshpop certificate must be a host ssh certificate"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{Serial: 123455, CertType: ssh.HostCert}, sshHostSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", p.GetName(), testAudiences.SSHRenew[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				cert:  cert,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if cert, err := tc.p.AuthorizeSSHRenew(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.Nonce, cert.Nonce)
				}
			}
		})
	}
}

func TestSSHPOP_AuthorizeSSHRekey(t *testing.T) {
	key, err := pemutil.Read("./testdata/secrets/ssh_user_ca_key")
	assert.FatalError(t, err)
	userSigner, ok := key.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh user signing key to crypto signer")
	sshUserSigner, err := ssh.NewSignerFromSigner(userSigner)
	assert.FatalError(t, err)

	hostKey, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
	assert.FatalError(t, err)
	hostSigner, ok := hostKey.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh host signing key to crypto signer")
	sshHostSigner, err := ssh.NewSignerFromSigner(hostSigner)
	assert.FatalError(t, err)

	type test struct {
		p     *SSHPOP
		token string
		cert  *ssh.Certificate
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("sshpop.AuthorizeSSHRekey: sshpop.authorizeToken; error extracting sshpop header from token: extractSSHPOPCert; error parsing token: "),
			}
		},
		"fail/not-host-cert": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshUserSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("sshpop certificate must be a host ssh certificate"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			cert, jwk, err := createSSHCert(&ssh.Certificate{Serial: 123455, CertType: ssh.HostCert}, sshHostSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", p.GetName(), testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				cert:  cert,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if cert, opts, err := tc.p.AuthorizeSSHRekey(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 4, opts)
					for _, o := range opts {
						switch v := o.(type) {
						case Interface:
						case *sshDefaultPublicKeyValidator:
						case *sshCertDefaultValidator:
						case *sshCertValidityValidator:
							assert.Equals(t, v.Claimer, tc.p.ctl.Claimer)
						default:
							assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
						}
					}
					assert.Equals(t, tc.cert.Nonce, cert.Nonce)
				}
			}
		})
	}
}

func TestSSHPOP_ExtractSSHPOPCert(t *testing.T) {
	hostKey, err := pemutil.Read("./testdata/secrets/ssh_host_ca_key")
	assert.FatalError(t, err)
	hostSigner, ok := hostKey.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh host signing key to crypto signer")
	sshHostSigner, err := ssh.NewSignerFromSigner(hostSigner)
	assert.FatalError(t, err)

	type test struct {
		token string
		cert  *ssh.Certificate
		jwk   *jose.JSONWebKey
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			return test{
				token: "foo",
				err:   errors.New("extractSSHPOPCert; error parsing token"),
			}
		},
		"fail/sshpop-missing": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateToken("sub", "sshpop-provisioner", testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk)
			assert.FatalError(t, err)
			return test{
				token: tok,
				err:   errors.New("extractSSHPOPCert; token missing sshpop header"),
			}
		},
		"fail/wrong-sshpop-type": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", "sshpop-provisioner", testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, func(so *jose.SignerOptions) error {
					so.WithHeader("sshpop", 12345)
					return nil
				})
			assert.FatalError(t, err)
			return test{
				token: tok,
				err:   errors.New("extractSSHPOPCert; error unexpected type for sshpop header: "),
			}
		},
		"fail/base64decode-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", "sshpop-provisioner", testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, func(so *jose.SignerOptions) error {
					so.WithHeader("sshpop", "!@#$%^&*")
					return nil
				})
			assert.FatalError(t, err)
			return test{
				token: tok,
				err:   errors.New("extractSSHPOPCert; error base64 decoding sshpop header: illegal base64"),
			}
		},
		"fail/parsing-sshpop-pubkey": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateToken("123455", "sshpop-provisioner", testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, func(so *jose.SignerOptions) error {
					so.WithHeader("sshpop", base64.StdEncoding.EncodeToString([]byte("foo")))
					return nil
				})
			assert.FatalError(t, err)
			return test{
				token: tok,
				err:   errors.New("extractSSHPOPCert; error parsing ssh public key"),
			}
		},
		"ok": func(t *testing.T) test {
			cert, jwk, err := createSSHCert(&ssh.Certificate{Serial: 123455, CertType: ssh.HostCert}, sshHostSigner)

			assert.FatalError(t, err)
			tok, err := generateToken("123455", "sshpop-provisioner", testAudiences.SSHRekey[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				token: tok,
				jwk:   jwk,
				cert:  cert,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if cert, jwt, err := ExtractSSHPOPCert(tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.Nonce, cert.Nonce)
					assert.Equals(t, tc.jwk.KeyID, jwt.Headers[0].KeyID)
				}
			}
		})
	}
}
