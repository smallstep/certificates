package ca

import (
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func getTestProvisioner(t *testing.T, caURL string) *Provisioner {
	jwk, err := jose.ReadKey("testdata/secrets/ott_mariano_priv.jwk", jose.WithPassword([]byte("password")))
	if err != nil {
		t.Fatal(err)
	}

	cert, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(caURL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	return &Provisioner{
		Client:        client,
		name:          "mariano",
		kid:           "FLIV7q23CXHrg75J2OSbvzwKJJqoxCYixjmsJirneOg",
		audience:      client.endpoint.ResolveReference(&url.URL{Path: "/1.0/sign"}).String(),
		sshAudience:   client.endpoint.ResolveReference(&url.URL{Path: "/1.0/ssh/sign"}).String(),
		fingerprint:   x509util.Fingerprint(cert),
		jwk:           jwk,
		tokenLifetime: 5 * time.Minute,
	}
}

func mustParseSigned(t *testing.T, tok string, key, dest any) {
	t.Helper()

	jwt, err := jose.ParseSigned(tok)
	require.NoError(t, err)
	require.NoError(t, jwt.Claims(key, dest))
}

func TestNewProvisioner(t *testing.T) {
	ca := startCATestServer(t)
	defer ca.Close()
	want := getTestProvisioner(t, ca.URL)

	caBundle, err := os.ReadFile("testdata/secrets/root_ca.crt")
	require.NoError(t, err)

	type args struct {
		name         string
		kid          string
		caURL        string
		password     []byte
		clientOption ClientOption
	}
	tests := []struct {
		name    string
		args    args
		want    *Provisioner
		wantErr bool
	}{
		{"ok", args{want.name, want.kid, ca.URL, []byte("password"), WithRootFile("testdata/secrets/root_ca.crt")}, want, false},
		{"ok-by-name", args{want.name, "", ca.URL, []byte("password"), WithRootFile("testdata/secrets/root_ca.crt")}, want, false},
		{"ok-with-bundle", args{want.name, want.kid, ca.URL, []byte("password"), WithCABundle(caBundle)}, want, false},
		{"ok-with-fingerprint", args{want.name, want.kid, ca.URL, []byte("password"), WithRootSHA256(want.fingerprint)}, want, false},
		{"fail-bad-kid", args{want.name, "bad-kid", ca.URL, []byte("password"), WithRootFile("testdata/secrets/root_ca.crt")}, nil, true},
		{"fail-empty-name", args{"", want.kid, ca.URL, []byte("password"), WithRootFile("testdata/secrets/root_ca.crt")}, nil, true},
		{"fail-bad-name", args{"bad-name", "", ca.URL, []byte("password"), WithRootFile("testdata/secrets/root_ca.crt")}, nil, true},
		{"fail-by-password", args{want.name, want.kid, ca.URL, []byte("bad-password"), WithRootFile("testdata/secrets/root_ca.crt")}, nil, true},
		{"fail-by-password-no-kid", args{want.name, "", ca.URL, []byte("bad-password"), WithRootFile("testdata/secrets/root_ca.crt")}, nil, true},
		{"fail-bad-certificate", args{want.name, want.kid, ca.URL, []byte("password"), WithRootFile("testdata/secrets/federated_ca.crt")}, nil, true},
		{"fail-not-found-certificate", args{want.name, want.kid, ca.URL, []byte("password"), WithRootFile("testdata/secrets/missing.crt")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProvisioner(tt.args.name, tt.args.kid, tt.args.caURL, tt.args.password, tt.args.clientOption)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProvisioner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Client won't match.
			// Make sure it does.
			if got != nil {
				got.Client = want.Client
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewProvisioner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvisioner_Getters(t *testing.T) {
	p := getTestProvisioner(t, "https://127.0.0.1:9000")
	if got := p.Name(); got != p.name {
		t.Errorf("Provisioner.Name() = %v, want %v", got, p.name)
	}
	if got := p.Kid(); got != p.kid {
		t.Errorf("Provisioner.Kid() = %v, want %v", got, p.kid)
	}
	if got := p.Fingerprint(); got != p.fingerprint {
		t.Errorf("Provisioner.Fingerprint() = %v, want %v", got, p.kid)
	}
	if got := p.Audience(); got != p.audience {
		t.Errorf("Provisioner.Audience() = %v, want %v", got, p.kid)
	}
	if got := p.SSHAudience(); got != p.sshAudience {
		t.Errorf("Provisioner.SSHAudience() = %v, want %v", got, p.kid)
	}
}

func TestProvisioner_Setters(t *testing.T) {
	p := getTestProvisioner(t, "https://127.0.0.1:9000")
	u, err := url.Parse(p.GetCaURL())
	require.NoError(t, err)

	p.SetFingerprint("71498a347624fe99e1baff52d57d04a75be9c695c67bd6b0a08903e809f7497d")
	p.SetAudience(u.ResolveReference(&url.URL{Path: "/1.0/revoke"}).String())
	p.SetSSHAudience(u.ResolveReference(&url.URL{Path: "/1.0/ssh/revoke"}).String())

	tok, err := p.Token("test@example.com")
	require.NoError(t, err)
	claims := make(map[string]any)
	mustParseSigned(t, tok, p.jwk.Public(), &claims)
	assert.Equal(t, "71498a347624fe99e1baff52d57d04a75be9c695c67bd6b0a08903e809f7497d", claims["sha"])
	assert.Equal(t, "https://127.0.0.1:9000/1.0/revoke", claims["aud"])

	tok, err = p.SSHToken("user", "test@example.com", []string{"test"})
	require.NoError(t, err)
	claims = make(map[string]any)
	mustParseSigned(t, tok, p.jwk.Public(), &claims)
	assert.Equal(t, "71498a347624fe99e1baff52d57d04a75be9c695c67bd6b0a08903e809f7497d", claims["sha"])
	assert.Equal(t, "https://127.0.0.1:9000/1.0/ssh/revoke", claims["aud"])
}

func TestProvisioner_Token(t *testing.T) {
	p := getTestProvisioner(t, "https://127.0.0.1:9000")
	sha := "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7"

	type fields struct {
		name          string
		kid           string
		fingerprint   string
		jwk           *jose.JSONWebKey
		tokenLifetime time.Duration
	}
	type args struct {
		subject string
		sans    []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", nil}, false},
		{"ok-with-san", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", []string{"foo.smallstep.com"}}, false},
		{"ok-with-sans", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", []string{"foo.smallstep.com", "127.0.0.1"}}, false},
		{"fail-no-subject", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"", []string{"foo.smallstep.com"}}, true},
		{"fail-no-key", fields{p.name, p.kid, sha, &jose.JSONWebKey{}, p.tokenLifetime}, args{"subject", nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provisioner{
				name:          tt.fields.name,
				kid:           tt.fields.kid,
				audience:      "https://127.0.0.1:9000/1.0/sign",
				fingerprint:   tt.fields.fingerprint,
				jwk:           tt.fields.jwk,
				tokenLifetime: tt.fields.tokenLifetime,
			}
			got, err := p.Token(tt.args.subject, tt.args.sans...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provisioner.Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr == false {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Error(err)
					return
				}
				var claims jose.Claims
				if err := jwt.Claims(tt.fields.jwk.Public(), &claims); err != nil {
					t.Error(err)
					return
				}
				if err := claims.ValidateWithLeeway(jose.Expected{
					Audience: []string{"https://127.0.0.1:9000/1.0/sign"},
					Issuer:   tt.fields.name,
					Subject:  tt.args.subject,
					Time:     time.Now().UTC(),
				}, time.Minute); err != nil {
					t.Error(err)
					return
				}
				lifetime := claims.Expiry.Time().Sub(claims.NotBefore.Time())
				if lifetime != tt.fields.tokenLifetime {
					t.Errorf("Claims token life time = %s, want %s", lifetime, tt.fields.tokenLifetime)
				}
				allClaims := make(map[string]interface{})
				if err := jwt.Claims(tt.fields.jwk.Public(), &allClaims); err != nil {
					t.Error(err)
					return
				}
				if v, ok := allClaims["sha"].(string); !ok || v != sha {
					t.Errorf("Claim sha = %s, want %s", v, sha)
				}
				if len(tt.args.sans) == 0 {
					if v, ok := allClaims["sans"].([]interface{}); !ok || !reflect.DeepEqual(v, []interface{}{tt.args.subject}) {
						t.Errorf("Claim sans = %s, want %s", v, []interface{}{tt.args.subject})
					}
				} else {
					want := []interface{}{}
					for _, s := range tt.args.sans {
						want = append(want, s)
					}
					if v, ok := allClaims["sans"].([]interface{}); !ok || !reflect.DeepEqual(v, want) {
						t.Errorf("Claim sans = %s, want %s", v, want)
					}
				}
				if v, ok := allClaims["jti"].(string); !ok || v == "" {
					t.Errorf("Claim jti = %s, want not blank", v)
				}
			}
		})
	}
}

func TestProvisioner_IPv6Token(t *testing.T) {
	p := getTestProvisioner(t, "https://[::1]:9000")
	sha := "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7"

	type fields struct {
		name          string
		kid           string
		fingerprint   string
		jwk           *jose.JSONWebKey
		tokenLifetime time.Duration
	}
	type args struct {
		subject string
		sans    []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", nil}, false},
		{"ok-with-san", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", []string{"foo.smallstep.com"}}, false},
		{"ok-with-sans", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"subject", []string{"foo.smallstep.com", "127.0.0.1"}}, false},
		{"fail-no-subject", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"", []string{"foo.smallstep.com"}}, true},
		{"fail-no-key", fields{p.name, p.kid, sha, &jose.JSONWebKey{}, p.tokenLifetime}, args{"subject", nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provisioner{
				name:          tt.fields.name,
				kid:           tt.fields.kid,
				audience:      "https://[::1]:9000/1.0/sign",
				fingerprint:   tt.fields.fingerprint,
				jwk:           tt.fields.jwk,
				tokenLifetime: tt.fields.tokenLifetime,
			}
			got, err := p.Token(tt.args.subject, tt.args.sans...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provisioner.Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr == false {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Error(err)
					return
				}
				var claims jose.Claims
				if err := jwt.Claims(tt.fields.jwk.Public(), &claims); err != nil {
					t.Error(err)
					return
				}
				if err := claims.ValidateWithLeeway(jose.Expected{
					Audience: []string{"https://[::1]:9000/1.0/sign"},
					Issuer:   tt.fields.name,
					Subject:  tt.args.subject,
					Time:     time.Now().UTC(),
				}, time.Minute); err != nil {
					t.Error(err)
					return
				}
				lifetime := claims.Expiry.Time().Sub(claims.NotBefore.Time())
				if lifetime != tt.fields.tokenLifetime {
					t.Errorf("Claims token life time = %s, want %s", lifetime, tt.fields.tokenLifetime)
				}
				allClaims := make(map[string]interface{})
				if err := jwt.Claims(tt.fields.jwk.Public(), &allClaims); err != nil {
					t.Error(err)
					return
				}
				if v, ok := allClaims["sha"].(string); !ok || v != sha {
					t.Errorf("Claim sha = %s, want %s", v, sha)
				}
				if len(tt.args.sans) == 0 {
					if v, ok := allClaims["sans"].([]interface{}); !ok || !reflect.DeepEqual(v, []interface{}{tt.args.subject}) {
						t.Errorf("Claim sans = %s, want %s", v, []interface{}{tt.args.subject})
					}
				} else {
					want := []interface{}{}
					for _, s := range tt.args.sans {
						want = append(want, s)
					}
					if v, ok := allClaims["sans"].([]interface{}); !ok || !reflect.DeepEqual(v, want) {
						t.Errorf("Claim sans = %s, want %s", v, want)
					}
				}
				if v, ok := allClaims["jti"].(string); !ok || v == "" {
					t.Errorf("Claim jti = %s, want not blank", v)
				}
			}
		})
	}
}

func TestProvisioner_SSHToken(t *testing.T) {
	p := getTestProvisioner(t, "https://127.0.0.1:9000")
	sha := "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7"

	type fields struct {
		name          string
		kid           string
		fingerprint   string
		jwk           *jose.JSONWebKey
		tokenLifetime time.Duration
	}
	type args struct {
		certType   string
		keyID      string
		principals []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"user", "foo@smallstep.com", []string{"foo"}}, false},
		{"ok host", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"host", "foo.smallstep.com", []string{"foo.smallstep.com"}}, false},
		{"ok multiple principals", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"user", "foo@smallstep.com", []string{"foo", "bar"}}, false},
		{"fail-no-subject", fields{p.name, p.kid, sha, p.jwk, p.tokenLifetime}, args{"user", "", []string{"foo"}}, true},
		{"fail-no-key", fields{p.name, p.kid, sha, &jose.JSONWebKey{}, p.tokenLifetime}, args{"user", "foo@smallstep.com", []string{"foo"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provisioner{
				name:          tt.fields.name,
				kid:           tt.fields.kid,
				audience:      "https://127.0.0.1:9000/1.0/sign",
				sshAudience:   "https://127.0.0.1:9000/1.0/ssh/sign",
				fingerprint:   tt.fields.fingerprint,
				jwk:           tt.fields.jwk,
				tokenLifetime: tt.fields.tokenLifetime,
			}
			got, err := p.SSHToken(tt.args.certType, tt.args.keyID, tt.args.principals)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provisioner.SSHToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr == false {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Error(err)
					return
				}
				var claims jose.Claims
				if err := jwt.Claims(tt.fields.jwk.Public(), &claims); err != nil {
					t.Error(err)
					return
				}
				if err := claims.ValidateWithLeeway(jose.Expected{
					Audience: []string{"https://127.0.0.1:9000/1.0/ssh/sign"},
					Issuer:   tt.fields.name,
					Subject:  tt.args.keyID,
					Time:     time.Now().UTC(),
				}, time.Minute); err != nil {
					t.Error(err)
					return
				}
				lifetime := claims.Expiry.Time().Sub(claims.NotBefore.Time())
				if lifetime != tt.fields.tokenLifetime {
					t.Errorf("Claims token life time = %s, want %s", lifetime, tt.fields.tokenLifetime)
				}
				allClaims := make(map[string]interface{})
				if err := jwt.Claims(tt.fields.jwk.Public(), &allClaims); err != nil {
					t.Error(err)
					return
				}
				if v, ok := allClaims["sha"].(string); !ok || v != sha {
					t.Errorf("Claim sha = %s, want %s", v, sha)
				}

				principals := make([]interface{}, len(tt.args.principals))
				for i, p := range tt.args.principals {
					principals[i] = p
				}
				want := map[string]interface{}{
					"ssh": map[string]interface{}{
						"certType":    tt.args.certType,
						"keyID":       tt.args.keyID,
						"principals":  principals,
						"validAfter":  "",
						"validBefore": "",
					},
				}
				if !reflect.DeepEqual(allClaims["step"], want) {
					t.Errorf("Claim step = %s, want %s", allClaims["step"], want)
				}
				if v, ok := allClaims["jti"].(string); !ok || v == "" {
					t.Errorf("Claim jti = %s, want not blank", v)
				}
			}
		})
	}
}
