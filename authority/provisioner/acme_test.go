//go:build !go1.18
// +build !go1.18

package provisioner

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestACMEChallenge_Validate(t *testing.T) {
	tests := []struct {
		name    string
		c       ACMEChallenge
		wantErr bool
	}{
		{"http-01", HTTP_01, false},
		{"dns-01", DNS_01, false},
		{"tls-alpn-01", TLS_ALPN_01, false},
		{"device-attest-01", DEVICE_ATTEST_01, false},
		{"uppercase", "HTTP-01", false},
		{"fail", "http-02", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ACMEChallenge.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEAttestationFormat_Validate(t *testing.T) {
	tests := []struct {
		name    string
		f       ACMEAttestationFormat
		wantErr bool
	}{
		{"apple", APPLE, false},
		{"step", STEP, false},
		{"tpm", TPM, false},
		{"uppercase", "APPLE", false},
		{"fail", "FOO", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.f.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ACMEAttestationFormat.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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
	appleCA, err := os.ReadFile("testdata/certs/apple-att-ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	yubicoCA, err := os.ReadFile("testdata/certs/yubico-piv-ca.crt")
	if err != nil {
		t.Fatal(err)
	}

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
		"fail-bad-challenge": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "bar", Challenges: []ACMEChallenge{HTTP_01, "zar"}},
				err: errors.New("acme challenge \"zar\" is not supported"),
			}
		},
		"fail-bad-attestation-format": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "bar", AttestationFormats: []ACMEAttestationFormat{APPLE, "zar"}},
				err: errors.New("acme attestation format \"zar\" is not supported"),
			}
		},
		"fail-parse-attestation-roots": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "bar", AttestationRoots: []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----")},
				err: errors.New("error parsing attestationRoots: malformed certificate"),
			}
		},
		"fail-empty-attestation-roots": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "bar", AttestationRoots: []byte("\n")},
				err: errors.New("error parsing attestationRoots: no certificates found"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{Name: "foo", Type: "bar"},
			}
		},
		"ok attestation": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:               "foo",
					Type:               "bar",
					Challenges:         []ACMEChallenge{DNS_01, DEVICE_ATTEST_01},
					AttestationFormats: []ACMEAttestationFormat{APPLE, STEP},
					AttestationRoots:   bytes.Join([][]byte{appleCA, yubicoCA}, []byte("\n")),
				},
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
			t.Log(string(tc.p.AttestationRoots))
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
				sc, ok := err.(render.StatusCodedError)
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
					sc, ok := err.(render.StatusCodedError)
					assert.Fatal(t, ok, "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) && assert.NotNil(t, opts) {
					assert.Equals(t, 8, len(opts)) // number of SignOptions returned
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
						case *WebhookController:
							assert.Len(t, 0, v.webhooks)
						default:
							assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
						}
					}
				}
			}
		})
	}
}

func TestACME_IsChallengeEnabled(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		Challenges []ACMEChallenge
	}
	type args struct {
		ctx       context.Context
		challenge ACMEChallenge
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"ok http-01", fields{nil}, args{ctx, HTTP_01}, true},
		{"ok dns-01", fields{nil}, args{ctx, DNS_01}, true},
		{"ok tls-alpn-01", fields{[]ACMEChallenge{}}, args{ctx, TLS_ALPN_01}, true},
		{"fail device-attest-01", fields{[]ACMEChallenge{}}, args{ctx, "device-attest-01"}, false},
		{"ok http-01 enabled", fields{[]ACMEChallenge{"http-01"}}, args{ctx, "HTTP-01"}, true},
		{"ok dns-01 enabled", fields{[]ACMEChallenge{"http-01", "dns-01"}}, args{ctx, DNS_01}, true},
		{"ok tls-alpn-01 enabled", fields{[]ACMEChallenge{"http-01", "dns-01", "tls-alpn-01"}}, args{ctx, TLS_ALPN_01}, true},
		{"ok device-attest-01 enabled", fields{[]ACMEChallenge{"device-attest-01", "dns-01"}}, args{ctx, DEVICE_ATTEST_01}, true},
		{"fail http-01", fields{[]ACMEChallenge{"dns-01"}}, args{ctx, "http-01"}, false},
		{"fail dns-01", fields{[]ACMEChallenge{"http-01", "tls-alpn-01"}}, args{ctx, "dns-01"}, false},
		{"fail tls-alpn-01", fields{[]ACMEChallenge{"http-01", "dns-01", "device-attest-01"}}, args{ctx, "tls-alpn-01"}, false},
		{"fail device-attest-01", fields{[]ACMEChallenge{"http-01", "dns-01"}}, args{ctx, "device-attest-01"}, false},
		{"fail unknown", fields{[]ACMEChallenge{"http-01", "dns-01", "tls-alpn-01", "device-attest-01"}}, args{ctx, "unknown"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				Challenges: tt.fields.Challenges,
			}
			if got := p.IsChallengeEnabled(tt.args.ctx, tt.args.challenge); got != tt.want {
				t.Errorf("ACME.AuthorizeChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACME_IsAttestationFormatEnabled(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		AttestationFormats []ACMEAttestationFormat
	}
	type args struct {
		ctx    context.Context
		format ACMEAttestationFormat
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"ok", fields{[]ACMEAttestationFormat{APPLE, STEP, TPM}}, args{ctx, TPM}, true},
		{"ok empty apple", fields{nil}, args{ctx, APPLE}, true},
		{"ok empty step", fields{nil}, args{ctx, STEP}, true},
		{"ok empty tpm", fields{[]ACMEAttestationFormat{}}, args{ctx, "tpm"}, true},
		{"ok uppercase", fields{[]ACMEAttestationFormat{APPLE, STEP, TPM}}, args{ctx, "STEP"}, true},
		{"fail apple", fields{[]ACMEAttestationFormat{STEP, TPM}}, args{ctx, APPLE}, false},
		{"fail step", fields{[]ACMEAttestationFormat{APPLE, TPM}}, args{ctx, STEP}, false},
		{"fail step", fields{[]ACMEAttestationFormat{APPLE, STEP}}, args{ctx, TPM}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				AttestationFormats: tt.fields.AttestationFormats,
			}
			if got := p.IsAttestationFormatEnabled(tt.args.ctx, tt.args.format); got != tt.want {
				t.Errorf("ACME.IsAttestationFormatEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
