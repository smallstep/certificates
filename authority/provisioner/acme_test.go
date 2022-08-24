package provisioner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestACME_Getters(t *testing.T) {
	p, err := generateACME()
	assert.FatalError(t, err)
	id := "acme/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("ACME.GetID() = %v, want %v", got, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("ACME.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeACME {
		t.Errorf("ACME.GetType() = %v, want %v", got, TypeACME)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("ACME.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestACME_Init(t *testing.T) {
	type ProvisionerValidateTest struct {
		p   *ACME
		err error
	}
	tests := map[string]func(*testing.T) ProvisionerValidateTest{
		"fail-empty": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail-empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Type: "ACME",
				},
				err: errors.New("provisioner name cannot be empty"),
			}
		},
		"fail-empty-type": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo"},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail-bad-claims": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "bar", Claims: &Claims{DefaultTLSDur: &Duration{0}}},
				err: errors.New("claims: MinTLSCertDuration must be greater than 0"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{Name: "foo", Type: "bar"},
			}
		},
	}

	config := Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	}
	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			err := tc.p.Init(config)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestACME_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	type test struct {
		p    *ACME
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func(*testing.T) test{
		"fail/renew-disabled": func(t *testing.T) test {
			p, err := generateACME()
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
			p, err := generateACME()
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
				sc, ok := render.AsStatusCodedError(err)
				assert.Fatal(t, ok, "error does not implement StatusCodedError interface")
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

func TestACME_AuthorizeSign(t *testing.T) {
	type test struct {
		p     *ACME
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"ok": func(t *testing.T) test {
			p, err := generateACME()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := render.AsStatusCodedError(err)
					assert.Fatal(t, ok, "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) && assert.NotNil(t, opts) {
					assert.Equals(t, 7, len(opts)) // number of SignOptions returned
					for _, o := range opts {
						switch v := o.(type) {
						case *ACME:
						case *provisionerExtensionOption:
							assert.Equals(t, v.Type, TypeACME)
							assert.Equals(t, v.Name, tc.p.GetName())
							assert.Equals(t, v.CredentialID, "")
							assert.Len(t, 0, v.KeyValuePairs)
						case *forceCNOption:
							assert.Equals(t, v.ForceCN, tc.p.ForceCN)
						case profileDefaultDuration:
							assert.Equals(t, time.Duration(v), tc.p.ctl.Claimer.DefaultTLSCertDuration())
						case defaultPublicKeyValidator:
						case *validityValidator:
							assert.Equals(t, v.min, tc.p.ctl.Claimer.MinTLSCertDuration())
							assert.Equals(t, v.max, tc.p.ctl.Claimer.MaxTLSCertDuration())
						case *x509NamePolicyValidator:
							assert.Equals(t, nil, v.policyEngine)
						default:
							assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
						}
					}
				}
			}
		})
	}
}

func TestACME_AuthorizeChallenge(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		Challenges []string
	}
	type args struct {
		ctx       context.Context
		challenge string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok http-01", fields{nil}, args{ctx, "http-01"}, false},
		{"ok dns-01", fields{nil}, args{ctx, "dns-01"}, false},
		{"ok tls-alpn-01", fields{[]string{}}, args{ctx, "tls-alpn-01"}, false},
		{"fail device-attest-01", fields{[]string{}}, args{ctx, "device-attest-01"}, true},
		{"ok http-01 enabled", fields{[]string{"http-01"}}, args{ctx, "http-01"}, false},
		{"ok dns-01 enabled", fields{[]string{"http-01", "dns-01"}}, args{ctx, "dns-01"}, false},
		{"ok tls-alpn-01 enabled", fields{[]string{"http-01", "dns-01", "tls-alpn-01"}}, args{ctx, "tls-alpn-01"}, false},
		{"ok device-attest-01 enabled", fields{[]string{"device-attest-01", "dns-01"}}, args{ctx, "device-attest-01"}, false},
		{"fail http-01", fields{[]string{"dns-01"}}, args{ctx, "http-01"}, true},
		{"fail dns-01", fields{[]string{"http-01", "tls-alpn-01"}}, args{ctx, "dns-01"}, true},
		{"fail tls-alpn-01", fields{[]string{"http-01", "dns-01", "device-attest-01"}}, args{ctx, "tls-alpn-01"}, true},
		{"fail device-attest-01", fields{[]string{"http-01", "dns-01"}}, args{ctx, "device-attest-01"}, true},
		{"fail unknown", fields{[]string{"http-01", "dns-01", "tls-alpn-01", "device-attest-01"}}, args{ctx, "unknown"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				Challenges: tt.fields.Challenges,
			}
			if err := p.AuthorizeChallenge(tt.args.ctx, tt.args.challenge); (err != nil) != tt.wantErr {
				t.Errorf("ACME.AuthorizeChallenge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
