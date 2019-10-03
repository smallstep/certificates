package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
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
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}

	type fields struct {
		Type                  string
		Name                  string
		ClientID              string
		ClientSecret          string
		ConfigurationEndpoint string
		Claims                *Claims
		Admins                []string
		Domains               []string
		ListenAddress         string
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
		{"ok", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil, nil, ""}, args{config}, false},
		{"ok-admins", fields{"oidc", "name", "client-id", "client-secret", srv.URL + "/.well-known/openid-configuration", nil, []string{"foo@smallstep.com"}, nil, ""}, args{config}, false},
		{"ok-domains", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil, []string{"smallstep.com"}, ""}, args{config}, false},
		{"ok-listen-port", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil, nil, ":10000"}, args{config}, false},
		{"ok-listen-host-port", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil, nil, "127.0.0.1:10000"}, args{config}, false},
		{"ok-no-secret", fields{"oidc", "name", "client-id", "", srv.URL, nil, nil, nil, ""}, args{config}, false},
		{"no-name", fields{"oidc", "", "client-id", "client-secret", srv.URL, nil, nil, nil, ""}, args{config}, true},
		{"no-type", fields{"", "name", "client-id", "client-secret", srv.URL, nil, nil, nil, ""}, args{config}, true},
		{"no-client-id", fields{"oidc", "name", "", "client-secret", srv.URL, nil, nil, nil, ""}, args{config}, true},
		{"no-configuration", fields{"oidc", "name", "client-id", "client-secret", "", nil, nil, nil, ""}, args{config}, true},
		{"bad-configuration", fields{"oidc", "name", "client-id", "client-secret", srv.URL + "/random", nil, nil, nil, ""}, args{config}, true},
		{"bad-claims", fields{"oidc", "name", "client-id", "client-secret", srv.URL + "/.well-known/openid-configuration", badClaims, nil, nil, ""}, args{config}, true},
		{"bad-parse-url", fields{"oidc", "name", "client-id", "client-secret", ":", nil, nil, nil, ""}, args{config}, true},
		{"bad-get-url", fields{"oidc", "name", "client-id", "client-secret", "https://", nil, nil, nil, ""}, args{config}, true},
		{"bad-listen-address", fields{"oidc", "name", "client-id", "client-secret", srv.URL, nil, nil, nil, "127.0.0.1"}, args{config}, true},
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
				Domains:               tt.fields.Domains,
				ListenAddress:         tt.fields.ListenAddress,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
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

func TestOIDC_authorizeToken(t *testing.T) {
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
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}

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
	// Invalid email
	failEmail, err := generateToken("subject", "the-issuer", p3.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	failDomain, err := generateToken("subject", "the-issuer", p3.ClientID, "name@example.com", []string{}, time.Now(), &keys.Keys[0])
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
	failExp, err := generateToken("subject", "the-issuer", p1.ClientID, "name@smallstep.com", []string{}, time.Now().Add(-360*time.Second), &keys.Keys[0])
	assert.FatalError(t, err)
	// not before
	failNbf, err := generateToken("subject", "the-issuer", p1.ClientID, "name@smallstep.com", []string{}, time.Now().Add(360*time.Second), &keys.Keys[0])
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
		{"fail-email", p3, args{failEmail}, true},
		{"fail-domain", p3, args{failDomain}, true},
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
			got, err := tt.prov.authorizeToken(tt.args.token)
			if (err != nil) != tt.wantErr {
				fmt.Println(tt)
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equals(t, got.Issuer, "the-issuer")
			}
		})
	}
}

func TestOIDC_AuthorizeSign(t *testing.T) {
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
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}

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
	// Admin email not in domains
	okAdmin, err := generateToken("subject", "the-issuer", p3.ClientID, "root@example.com", []string{"test.smallstep.com"}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Invalid email
	failEmail, err := generateToken("subject", "the-issuer", p3.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
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
		{"admin", p3, args{okAdmin}, false},
		{"fail-email", p3, args{failEmail}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			got, err := tt.prov.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				if assert.NotNil(t, got) {
					if tt.name == "admin" {
						assert.Len(t, 4, got)
					} else {
						assert.Len(t, 5, got)
					}
					for _, o := range got {
						switch v := o.(type) {
						case *provisionerExtensionOption:
							assert.Equals(t, v.Type, int(TypeOIDC))
							assert.Equals(t, v.Name, tt.prov.GetName())
							assert.Equals(t, v.CredentialID, tt.prov.ClientID)
							assert.Len(t, 0, v.KeyValuePairs)
						case profileDefaultDuration:
							assert.Equals(t, time.Duration(v), tt.prov.claimer.DefaultTLSCertDuration())
						case defaultPublicKeyValidator:
						case *validityValidator:
							assert.Equals(t, v.min, tt.prov.claimer.MinTLSCertDuration())
							assert.Equals(t, v.max, tt.prov.claimer.MaxTLSCertDuration())
						case emailOnlyIdentity:
							assert.Equals(t, string(v), "name@smallstep.com")
						default:
							assert.FatalError(t, errors.Errorf("unexpected sign option of type %T", v))
						}
					}
				}
			}
		})
	}
}

func TestOIDC_AuthorizeSign_SSH(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

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
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}

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
	// Admin email not in domains
	okAdmin, err := generateToken("subject", "the-issuer", p3.ClientID, "root@example.com", []string{}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Invalid email
	failEmail, err := generateToken("subject", "the-issuer", p3.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	pub := key.Public().Key
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.FatalError(t, err)

	userDuration := p1.claimer.DefaultUserSSHCertDuration()
	hostDuration := p1.claimer.DefaultHostSSHCertDuration()
	expectedUserOptions := &SSHOptions{
		CertType: "user", Principals: []string{"name"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration)),
	}
	expectedAdminOptions := &SSHOptions{
		CertType: "user", Principals: []string{"root"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration)),
	}
	expectedHostOptions := &SSHOptions{
		CertType: "host", Principals: []string{"smallstep.com"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		prov        *OIDC
		args        args
		expected    *SSHOptions
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SSHOptions{}, pub}, expectedUserOptions, false, false},
		{"ok-rsa2048", p1, args{t1, SSHOptions{}, rsa2048.Public()}, expectedUserOptions, false, false},
		{"ok-user", p1, args{t1, SSHOptions{CertType: "user"}, pub}, expectedUserOptions, false, false},
		{"ok-principals", p1, args{t1, SSHOptions{Principals: []string{"name"}}, pub}, expectedUserOptions, false, false},
		{"ok-options", p1, args{t1, SSHOptions{CertType: "user", Principals: []string{"name"}}, pub}, expectedUserOptions, false, false},
		{"admin", p3, args{okAdmin, SSHOptions{}, pub}, expectedAdminOptions, false, false},
		{"admin-user", p3, args{okAdmin, SSHOptions{CertType: "user"}, pub}, expectedAdminOptions, false, false},
		{"admin-principals", p3, args{okAdmin, SSHOptions{Principals: []string{"root"}}, pub}, expectedAdminOptions, false, false},
		{"admin-options", p3, args{okAdmin, SSHOptions{CertType: "user", Principals: []string{"name"}}, pub}, expectedUserOptions, false, false},
		{"admin-host", p3, args{okAdmin, SSHOptions{CertType: "host", Principals: []string{"smallstep.com"}}, pub}, expectedHostOptions, false, false},
		{"fail-rsa1024", p1, args{t1, SSHOptions{}, rsa1024.Public()}, expectedUserOptions, false, true},
		{"fail-user-host", p1, args{t1, SSHOptions{CertType: "host"}, pub}, nil, false, true},
		{"fail-user-principals", p1, args{t1, SSHOptions{Principals: []string{"root"}}, pub}, nil, false, true},
		{"fail-email", p3, args{failEmail, SSHOptions{}, pub}, nil, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignSSHMethod)
			got, err := tt.prov.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else if assert.NotNil(t, got) {
				cert, err := signSSHCertificate(tt.args.key, tt.args.sshOpts, got, signer.Key.(crypto.Signer))
				if (err != nil) != tt.wantSignErr {
					t.Errorf("SignSSH error = %v, wantSignErr %v", err, tt.wantSignErr)
				} else {
					if tt.wantSignErr {
						assert.Nil(t, cert)
					} else {
						assert.NoError(t, validateSSHCertificate(cert, tt.expected))
					}
				}
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
	p3, err := generateOIDC()
	assert.FatalError(t, err)
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}

	// Update configuration endpoints and initialize
	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p3.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))
	assert.FatalError(t, p3.Init(config))

	t1, err := generateSimpleToken("the-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	// Admin email not in domains
	okAdmin, err := generateToken("subject", "the-issuer", p3.ClientID, "root@example.com", []string{"test.smallstep.com"}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Invalid email
	failEmail, err := generateToken("subject", "the-issuer", p3.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
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
		{"ok1", p1, args{t1}, true},
		{"admin", p3, args{okAdmin}, false},
		{"fail-email", p3, args{failEmail}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.prov.AuthorizeRevoke(tt.args.token)
			if (err != nil) != tt.wantErr {
				fmt.Println(tt)
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
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
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

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

func Test_sanitizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{"equal", "name@smallstep.com", "name@smallstep.com"},
		{"domain-insensitive", "name@SMALLSTEP.COM", "name@smallstep.com"},
		{"local-sensitive", "NaMe@smallSTEP.CoM", "NaMe@smallstep.com"},
		{"multiple-@", "NaMe@NaMe@smallSTEP.CoM", "NaMe@NaMe@smallstep.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeEmail(tt.email); got != tt.want {
				t.Errorf("sanitizeEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
