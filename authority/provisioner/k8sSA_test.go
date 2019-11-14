package provisioner

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/jose"
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
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
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
				err:   errors.New("error validating token and extracting claims"),
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
				err:   errors.New("invalid token claims: square/go-jose/jwt: validation failed, invalid issuer claim (iss)"),
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

func TestK8sSA_AuthorizeSign(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		ctx   context.Context
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
			}
		},
		"fail/ssh-unimplemented": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				ctx:   NewContextWithMethod(context.Background(), SignSSHMethod),
				token: tok,
				err:   errors.Errorf("ssh certificates not enabled for k8s ServiceAccount provisioners"),
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
				ctx:   NewContextWithMethod(context.Background(), SignMethod),
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSign(tc.ctx, tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						tot := 0
						for _, o := range opts {
							switch v := o.(type) {
							case *provisionerExtensionOption:
								assert.Equals(t, v.Type, int(TypeK8sSA))
								assert.Equals(t, v.Name, tc.p.GetName())
								assert.Equals(t, v.CredentialID, "")
								assert.Len(t, 0, v.KeyValuePairs)
							case profileDefaultDuration:
								assert.Equals(t, time.Duration(v), tc.p.claimer.DefaultTLSCertDuration())
							case defaultPublicKeyValidator:
							case *validityValidator:
								assert.Equals(t, v.min, tc.p.claimer.MinTLSCertDuration())
								assert.Equals(t, v.max, tc.p.claimer.MaxTLSCertDuration())
							default:
								assert.FatalError(t, errors.Errorf("unexpected sign option of type %T", v))
							}
							tot++
						}
						assert.Equals(t, tot, 4)
					}
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
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
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
			if err := tc.p.AuthorizeRevoke(context.TODO(), tc.token); err != nil {
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
	p1, err := generateK8sSA(nil)
	assert.FatalError(t, err)
	p2, err := generateK8sSA(nil)
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		prov    *K8sSA
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenew(context.TODO(), tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("X5C.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
