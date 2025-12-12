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

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"wire-oidc-01", DEVICE_ATTEST_01, false},
		{"wire-dpop-01", DEVICE_ATTEST_01, false},
		{"uppercase", "HTTP-01", false},
		{"fail", "http-02", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
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
			err := tt.f.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestACME_Getters(t *testing.T) {
	p, err := generateACME()
	require.NoError(t, err)
	id := "acme/test@acme-provisioner.com"
	assert.Equal(t, id, p.GetID())
	assert.Equal(t, "test@acme-provisioner.com", p.GetName())
	assert.Equal(t, TypeACME, p.GetType())
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("ACME.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
	tokenID, err := p.GetTokenID("token")
	assert.Empty(t, tokenID)
	assert.Equal(t, ErrTokenFlowNotSupported, err)
}

func TestACME_Init(t *testing.T) {
	appleCA, err := os.ReadFile("testdata/certs/apple-att-ca.crt")
	require.NoError(t, err)
	yubicoCA, err := os.ReadFile("testdata/certs/yubico-piv-ca.crt")
	require.NoError(t, err)
	fakeWireDPoPKey := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`)

	type ProvisionerValidateTest struct {
		p   *ACME
		err error
	}
	tests := map[string]func(*testing.T) ProvisionerValidateTest{
		"fail/empty": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail/empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Type: "ACME",
				},
				err: errors.New("provisioner name cannot be empty"),
			}
		},
		"fail/empty-type": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo"},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail/bad-claims": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "ACME", Claims: &Claims{DefaultTLSDur: &Duration{0}}},
				err: errors.New("claims: MinTLSCertDuration must be greater than 0"),
			}
		},
		"fail/bad-challenge": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "ACME", Challenges: []ACMEChallenge{HTTP_01, "zar"}},
				err: errors.New("acme challenge \"zar\" is not supported"),
			}
		},
		"fail/bad-attestation-format": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "ACME", AttestationFormats: []ACMEAttestationFormat{APPLE, "zar"}},
				err: errors.New("acme attestation format \"zar\" is not supported"),
			}
		},
		"fail/parse-attestation-roots": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "ACME", AttestationRoots: []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----")},
				err: errors.New("error parsing attestationRoots: malformed certificate"),
			}
		},
		"fail/empty-attestation-roots": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &ACME{Name: "foo", Type: "ACME", AttestationRoots: []byte("\n")},
				err: errors.New("error parsing attestationRoots: no certificates found"),
			}
		},
		"fail/wire-missing-options": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:       "foo",
					Type:       "ACME",
					Challenges: []ACMEChallenge{WIREOIDC_01, WIREDPOP_01},
				},
				err: errors.New("failed initializing Wire options: failed getting Wire options: no options available"),
			}
		},
		"fail/wire-missing-wire-options": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:       "foo",
					Type:       "ACME",
					Challenges: []ACMEChallenge{WIREOIDC_01, WIREDPOP_01},
					Options:    &Options{},
				},
				err: errors.New("failed initializing Wire options: failed getting Wire options: no Wire options available"),
			}
		},
		"fail/wire-validate-options": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:       "foo",
					Type:       "ACME",
					Challenges: []ACMEChallenge{WIREOIDC_01, WIREDPOP_01},
					Options: &Options{
						Wire: &wire.Options{
							OIDC: &wire.OIDCOptions{},
							DPOP: &wire.DPOPOptions{
								SigningKey: fakeWireDPoPKey,
							},
						},
					},
				},
				err: errors.New("failed initializing Wire options: failed validating Wire options: failed initializing OIDC options: provider not set"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{Name: "foo", Type: "ACME"},
			}
		},
		"ok/attestation": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:               "foo",
					Type:               "ACME",
					Challenges:         []ACMEChallenge{DNS_01, DEVICE_ATTEST_01},
					AttestationFormats: []ACMEAttestationFormat{APPLE, STEP},
					AttestationRoots:   bytes.Join([][]byte{appleCA, yubicoCA}, []byte("\n")),
				},
			}
		},
		"ok/wire": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &ACME{
					Name:       "foo",
					Type:       "ACME",
					Challenges: []ACMEChallenge{WIREOIDC_01, WIREDPOP_01},
					Options: &Options{
						Wire: &wire.Options{
							OIDC: &wire.OIDCOptions{
								Provider: &wire.Provider{
									IssuerURL: "https://issuer.example.com",
								},
							},
							DPOP: &wire.DPOPOptions{
								SigningKey: fakeWireDPoPKey,
							},
						},
					},
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
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				return
			}

			assert.NoError(t, err)
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
			require.NoError(t, err)
			// disable renewal
			disable := true
			p.Claims = &Claims{DisableRenewal: &disable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			require.NoError(t, err)
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
			require.NoError(t, err)
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
			err := tc.p.AuthorizeRenew(context.Background(), tc.cert)
			if tc.err != nil {
				if assert.Implements(t, (*render.StatusCodedError)(nil), err) {
					var sc render.StatusCodedError
					if errors.As(err, &sc) {
						assert.Equal(t, tc.code, sc.StatusCode())
					}
				}
				assert.EqualError(t, err, tc.err.Error())
				return
			}

			assert.NoError(t, err)
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
			require.NoError(t, err)
			return test{
				p:     p,
				token: "foo",
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			opts, err := tc.p.AuthorizeSign(context.Background(), tc.token)
			if tc.err != nil {
				if assert.Implements(t, (*render.StatusCodedError)(nil), err) {
					var sc render.StatusCodedError
					if errors.As(err, &sc) {
						assert.Equal(t, tc.code, sc.StatusCode())
					}
				}
				assert.EqualError(t, err, tc.err.Error())
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, opts) {
				assert.Len(t, opts, 8) // number of SignOptions returned
				for _, o := range opts {
					switch v := o.(type) {
					case *ACME:
					case *provisionerExtensionOption:
						assert.Equal(t, v.Type, TypeACME)
						assert.Equal(t, v.Name, tc.p.GetName())
						assert.Equal(t, v.CredentialID, "")
						assert.Len(t, v.KeyValuePairs, 0)
					case *forceCNOption:
						assert.Equal(t, v.ForceCN, tc.p.ForceCN)
					case profileDefaultDuration:
						assert.Equal(t, time.Duration(v), tc.p.ctl.Claimer.DefaultTLSCertDuration())
					case defaultPublicKeyValidator:
					case *validityValidator:
						assert.Equal(t, v.min, tc.p.ctl.Claimer.MinTLSCertDuration())
						assert.Equal(t, v.max, tc.p.ctl.Claimer.MaxTLSCertDuration())
					case *x509NamePolicyValidator:
						assert.Equal(t, nil, v.policyEngine)
					case *WebhookController:
						assert.Len(t, v.webhooks, 0)
					default:
						require.NoError(t, fmt.Errorf("unexpected sign option of type %T", v))
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
		{"ok wire-oidc-01 enabled", fields{[]ACMEChallenge{"wire-oidc-01"}}, args{ctx, WIREOIDC_01}, true},
		{"ok wire-dpop-01 enabled", fields{[]ACMEChallenge{"wire-dpop-01"}}, args{ctx, WIREDPOP_01}, true},
		{"fail http-01", fields{[]ACMEChallenge{"dns-01"}}, args{ctx, "http-01"}, false},
		{"fail dns-01", fields{[]ACMEChallenge{"http-01", "tls-alpn-01"}}, args{ctx, "dns-01"}, false},
		{"fail tls-alpn-01", fields{[]ACMEChallenge{"http-01", "dns-01", "device-attest-01"}}, args{ctx, "tls-alpn-01"}, false},
		{"fail device-attest-01", fields{[]ACMEChallenge{"http-01", "dns-01"}}, args{ctx, "device-attest-01"}, false},
		{"fail wire-oidc-01", fields{[]ACMEChallenge{"http-01", "dns-01"}}, args{ctx, "wire-oidc-01"}, false},
		{"fail wire-dpop-01", fields{[]ACMEChallenge{"http-01", "dns-01"}}, args{ctx, "wire-dpop-01"}, false},
		{"fail unknown", fields{[]ACMEChallenge{"http-01", "dns-01", "tls-alpn-01", "device-attest-01"}}, args{ctx, "unknown"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				Challenges: tt.fields.Challenges,
			}
			got := p.IsChallengeEnabled(tt.args.ctx, tt.args.challenge)
			assert.Equal(t, tt.want, got)
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
			got := p.IsAttestationFormatEnabled(tt.args.ctx, tt.args.format)
			assert.Equal(t, tt.want, got)
		})
	}
}
