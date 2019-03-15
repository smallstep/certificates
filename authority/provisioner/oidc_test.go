package provisioner

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/jose"
)

func Test_openIDConfiguration_Validate(t *testing.T) {
	type fields struct {
		Issuer    string
		JWKSetURI string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"the-issuer", "the-jwks-uri"}, false},
		{"no-issuer", fields{"", "the-jwks-uri"}, true},
		{"no-jwks-uri", fields{"the-issuer", ""}, true},
		{"empty", fields{"", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := openIDConfiguration{
				Issuer:    tt.fields.Issuer,
				JWKSetURI: tt.fields.JWKSetURI,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("openIDConfiguration.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDC_Getters(t *testing.T) {
	p, err := generateOIDC()
	assert.FatalError(t, err)
	if got := p.GetID(); got != p.ClientID {
		t.Errorf("OIDC.GetID() = %v, want %v", got, p.ClientID)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("OIDC.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeOIDC {
		t.Errorf("OIDC.GetType() = %v, want %v", got, TypeOIDC)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("OIDC.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestOIDC_Init(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()
	config := Config{
		Claims: globalProvisionerClaims,
	}

	type fields struct {
		Type                  string
		Name                  string
		ClientID              string
		ClientSecret          string
		ConfigurationEndpoint string
		Claims                *Claims
		Admins                []string
	}
	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{"oidc", "name", "client-id", "client-secret", srv.URL + "/openid-configuration", nil, nil}, args{config}, false},
		{"ok-admins", fields{"oidc", "name", "client-id", "client-secret", srv.URL + "/openid-configuration", nil, []string{"foo@smallstep.com"}}, args{config}, false},
		{"ok-no-secret", fields{"oidc", "name", "client-id", "", srv.URL + "/openid-configuration", nil, nil}, args{config}, false},
		{"no-name", fields{"oidc", "", "client-id", "client-secret", srv.URL + "/openid-configuration", nil, nil}, args{config}, true},
		{"no-type", fields{"", "name", "client-id", "client-secret", srv.URL + "/openid-configuration", nil, nil}, args{config}, true},
		{"no-client-id", fields{"oidc", "name", "", "client-secret", srv.URL + "/openid-configuration", nil, nil}, args{config}, true},
		{"no-configuration", fields{"oidc", "name", "client-id", "client-secret", "", nil, nil}, args{config}, true},
		{"bad-configuration", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil}, args{config}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OIDC{
				Type:                  tt.fields.Type,
				Name:                  tt.fields.Name,
				ClientID:              tt.fields.ClientID,
				ConfigurationEndpoint: tt.fields.ConfigurationEndpoint,
				Claims:                tt.fields.Claims,
				Admins:                tt.fields.Admins,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == false {
				assert.Len(t, 2, p.keyStore.keySet.Keys)
				assert.Equals(t, openIDConfiguration{
					Issuer:    "the-issuer",
					JWKSetURI: srv.URL + "/jwks_uri",
				}, p.configuration)
			}
		})
	}
}

func TestOIDC_Authorize(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	var keys jose.JSONWebKeySet
	assert.FatalError(t, getAndDecode(srv.URL+"/private", &keys))

	// Create test provisioners
	p1, err := generateOIDC()
	assert.FatalError(t, err)
	p2, err := generateOIDC()
	assert.FatalError(t, err)
	p3, err := generateOIDC()
	assert.FatalError(t, err)
	// Admin
	p3.Admins = []string{"name@smallstep.com"}

	// Update configuration endpoints and initialize
	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p2.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p3.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))
	assert.FatalError(t, p2.Init(config))
	assert.FatalError(t, p3.Init(config))

	t1, err := generateSimpleToken("the-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	t2, err := generateSimpleToken("the-issuer", p2.ClientID, &keys.Keys[1])
	assert.FatalError(t, err)
	t3, err := generateSimpleToken("the-issuer", p3.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)

	// Invalid tokens
	parts := strings.Split(t1, ".")
	key, err := generateJSONWebKey()
	assert.FatalError(t, err)
	// missing key
	failKey, err := generateSimpleToken("the-issuer", p1.ClientID, key)
	assert.FatalError(t, err)
	// invalid token
	failTok := "foo." + parts[1] + "." + parts[2]
	// invalid claims
	failClaims := parts[0] + ".foo." + parts[1]
	// invalid issuer
	failIss, err := generateSimpleToken("bad-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	// invalid audience
	failAud, err := generateSimpleToken("the-issuer", "foobar", &keys.Keys[0])
	assert.FatalError(t, err)
	// invalid signature
	failSig := t1[0 : len(t1)-2]
	// expired
	failExp, err := generateToken("subject", "the-issuer", p1.ClientID, []string{}, time.Now().Add(-360*time.Second), &keys.Keys[0])
	assert.FatalError(t, err)
	// not before
	failNbf, err := generateToken("subject", "the-issuer", p1.ClientID, []string{}, time.Now().Add(360*time.Second), &keys.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		wantErr bool
	}{
		{"ok1", p1, args{t1}, false},
		{"ok2", p2, args{t2}, false},
		{"admin", p3, args{t3}, false},
		{"fail-key", p1, args{failKey}, true},
		{"fail-token", p1, args{failTok}, true},
		{"fail-claims", p1, args{failClaims}, true},
		{"fail-issuer", p1, args{failIss}, true},
		{"fail-audience", p1, args{failAud}, true},
		{"fail-signature", p1, args{failSig}, true},
		{"fail-expired", p1, args{failExp}, true},
		{"fail-not-before", p1, args{failNbf}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.prov.Authorize(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				if tt.name == "admin" {
					assert.Len(t, 3, got)
				} else {
					assert.Len(t, 4, got)
				}
			}
		})
	}
}

func TestOIDC_AuthorizeRenewal(t *testing.T) {
	p1, err := generateOIDC()
	assert.FatalError(t, err)
	p2, err := generateOIDC()
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{
		globalClaims:   &globalProvisionerClaims,
		DisableRenewal: &disable,
	}

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("OIDC.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDC_AuthorizeRevoke(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	var keys jose.JSONWebKeySet
	assert.FatalError(t, getAndDecode(srv.URL+"/private", &keys))

	// Create test provisioners
	p1, err := generateOIDC()
	assert.FatalError(t, err)

	// Update configuration endpoints and initialize
	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))

	t1, err := generateSimpleToken("the-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		wantErr bool
	}{
		{"disabled", p1, args{t1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("OIDC.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
