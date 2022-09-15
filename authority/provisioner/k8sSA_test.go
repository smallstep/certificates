package provisioner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestK8sSA_Getters(t *testing.T) {
	p, err := generateK8sSA(nil)
	assert.FatalError(t, err)
	id := "k8ssa/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("K8sSA.GetID() = %v, want %v", got, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("K8sSA.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeK8sSA {
		t.Errorf("K8sSA.GetType() = %v, want %v", got, TypeK8sSA)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("K8sSA.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestK8sSA_authorizeToken(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"fail/not-implemented": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk)
			p.pubKeys = nil
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("k8ssa.authorizeToken; k8sSA TokenReview API integration not implemented"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/error-validating-token": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("k8ssa.authorizeToken; error validating k8sSA token and extracting claims"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			claims := getK8sSAPayload()
			claims.Claims.Issuer = "invalid"
			tok, err := generateK8sSAToken(jwk, claims)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.authorizeToken; invalid k8sSA token claims: square/go-jose/jwt: validation failed, invalid issuer claim (iss)"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
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
			if claims, err := tc.p.authorizeToken(tc.token, testAudiences.Sign); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.NotNil(t, claims)
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeRevoke(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeRevoke: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
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
			if err := tc.p.AuthorizeRevoke(context.Background(), tc.token); err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tc.code)
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestK8sSA_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	type test struct {
		p    *K8sSA
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func(*testing.T) test{
		"fail/renew-disabled": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			// disable renewal
			disable := true
			p.Claims = &Claims{DisableRenewal: &disable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p: p,
				cert: &x509.Certificate{
					NotBefore: now,
					NotAfter:  now.Add(time.Hour),
				},
				code: http.StatusUnauthorized,
				err:  fmt.Errorf("renew is disabled for provisioner '%s'", p.GetName()),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p: p,
				cert: &x509.Certificate{
					NotBefore: now,
					NotAfter:  now.Add(time.Hour),
				},
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeRenew(context.Background(), tc.cert); err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tc.code)
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestK8sSA_AuthorizeSign(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeSign: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
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
			if opts, err := tc.p.AuthorizeSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						for _, o := range opts {
							switch v := o.(type) {
							case *K8sSA:
							case certificateOptionsFunc:
							case *provisionerExtensionOption:
								assert.Equals(t, v.Type, TypeK8sSA)
								assert.Equals(t, v.Name, tc.p.GetName())
								assert.Equals(t, v.CredentialID, "")
								assert.Len(t, 0, v.KeyValuePairs)
							case profileDefaultDuration:
								assert.Equals(t, time.Duration(v), tc.p.ctl.Claimer.DefaultTLSCertDuration())
							case defaultPublicKeyValidator:
							case *validityValidator:
								assert.Equals(t, v.min, tc.p.ctl.Claimer.MinTLSCertDuration())
								assert.Equals(t, v.max, tc.p.ctl.Claimer.MaxTLSCertDuration())
							case *x509NamePolicyValidator:
								assert.Equals(t, nil, v.policyEngine)
							case *WebhookController:
								assert.Len(t, 0, v.webhooks)
							default:
								assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
							}
						}
						assert.Equals(t, 8, len(opts))
					}
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeSSHSign(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/sshCA-disabled": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			// disable sshCA
			disable := false
			p.Claims = &Claims{EnableSSHCA: &disable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   fmt.Errorf("k8ssa.AuthorizeSSHSign; sshCA is disabled for k8sSA provisioner '%s'", p.GetName()),
			}
		},
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeSSHSign: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
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
			if opts, err := tc.p.AuthorizeSSHSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						assert.Len(t, 9, opts)
						for _, o := range opts {
							switch v := o.(type) {
							case Interface:
							case sshCertificateOptionsFunc:
							case *sshCertOptionsRequireValidator:
								assert.Equals(t, v, &sshCertOptionsRequireValidator{CertType: true, KeyID: true, Principals: true})
							case *sshCertValidityValidator:
								assert.Equals(t, v.Claimer, tc.p.ctl.Claimer)
							case *sshDefaultPublicKeyValidator:
							case *sshCertDefaultValidator:
							case *sshDefaultDuration:
								assert.Equals(t, v.Claimer, tc.p.ctl.Claimer)
							case *sshNamePolicyValidator:
								assert.Equals(t, nil, v.userPolicyEngine)
								assert.Equals(t, nil, v.hostPolicyEngine)
							case *WebhookController:
								assert.Len(t, 0, v.webhooks)
							default:
								assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
							}
						}
					}
				}
			}
		})
	}
}
