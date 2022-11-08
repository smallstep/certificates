package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
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
	srv := generateJWKServer(3)
	defer srv.Close()

	var keys jose.JSONWebKeySet
	assert.FatalError(t, getAndDecode(srv.URL+"/private", &keys))

	issuer := "the-issuer"
	tenantID := "ab800f7d-2c87-45fb-b1d0-f90d0bc5ec25"
	tenantIssuer := "https://login.microsoftonline.com/" + tenantID + "/v2.0"

	// Create test provisioners
	p1, err := generateOIDC()
	assert.FatalError(t, err)
	p2, err := generateOIDC()
	assert.FatalError(t, err)
	p3, err := generateOIDC()
	assert.FatalError(t, err)
	// TenantID
	p2.TenantID = tenantID
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}

	// Update configuration endpoints and initialize
	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p2.ConfigurationEndpoint = srv.URL + "/common/.well-known/openid-configuration"
	p3.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))
	assert.FatalError(t, p2.Init(config))
	assert.FatalError(t, p3.Init(config))

	t1, err := generateSimpleToken(issuer, p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	t2, err := generateSimpleToken(tenantIssuer, p2.ClientID, &keys.Keys[1])
	assert.FatalError(t, err)
	t3, err := generateToken("subject", issuer, p3.ClientID, "name@smallstep.com", []string{}, time.Now(), &keys.Keys[2])
	assert.FatalError(t, err)
	t4, err := generateToken("subject", issuer, p3.ClientID, "foo@smallstep.com", []string{}, time.Now(), &keys.Keys[2])
	assert.FatalError(t, err)
	t5, err := generateToken("subject", issuer, p3.ClientID, "", []string{}, time.Now(), &keys.Keys[2])
	assert.FatalError(t, err)

	// Invalid email
	failDomain, err := generateToken("subject", issuer, p3.ClientID, "name@example.com", []string{}, time.Now(), &keys.Keys[2])
	assert.FatalError(t, err)
	// Invalid tokens
	parts := strings.Split(t1, ".")
	key, err := generateJSONWebKey()
	assert.FatalError(t, err)
	// missing key
	failKey, err := generateSimpleToken(issuer, p1.ClientID, key)
	assert.FatalError(t, err)
	// invalid token
	failTok := "foo." + parts[1] + "." + parts[2]
	// invalid claims
	failClaims := parts[0] + ".foo." + parts[1]
	// invalid issuer
	failIss, err := generateSimpleToken("bad-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	// invalid audience
	failAud, err := generateSimpleToken(issuer, "foobar", &keys.Keys[0])
	assert.FatalError(t, err)
	// invalid signature
	failSig := t1[0 : len(t1)-2]
	// expired
	failExp, err := generateToken("subject", issuer, p1.ClientID, "name@smallstep.com", []string{}, time.Now().Add(-360*time.Second), &keys.Keys[0])
	assert.FatalError(t, err)
	// not before
	failNbf, err := generateToken("subject", issuer, p1.ClientID, "name@smallstep.com", []string{}, time.Now().Add(360*time.Second), &keys.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name       string
		prov       *OIDC
		args       args
		code       int
		wantIssuer string
		wantErr    bool
	}{
		{"ok1", p1, args{t1}, http.StatusOK, issuer, false},
		{"ok tenantid", p2, args{t2}, http.StatusOK, tenantIssuer, false},
		{"ok admin", p3, args{t3}, http.StatusOK, issuer, false},
		{"ok domain", p3, args{t4}, http.StatusOK, issuer, false},
		{"ok no email", p3, args{t5}, http.StatusOK, issuer, false},
		{"fail-domain", p3, args{failDomain}, http.StatusUnauthorized, "", true},
		{"fail-key", p1, args{failKey}, http.StatusUnauthorized, "", true},
		{"fail-token", p1, args{failTok}, http.StatusUnauthorized, "", true},
		{"fail-claims", p1, args{failClaims}, http.StatusUnauthorized, "", true},
		{"fail-issuer", p1, args{failIss}, http.StatusUnauthorized, "", true},
		{"fail-audience", p1, args{failAud}, http.StatusUnauthorized, "", true},
		{"fail-signature", p1, args{failSig}, http.StatusUnauthorized, "", true},
		{"fail-expired", p1, args{failExp}, http.StatusUnauthorized, "", true},
		{"fail-not-before", p1, args{failNbf}, http.StatusUnauthorized, "", true},
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
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equals(t, got.Issuer, tt.wantIssuer)
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
	// No email
	noEmail, err := generateToken("subject", "the-issuer", p3.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		code    int
		wantErr bool
	}{
		{"ok1", p1, args{t1}, http.StatusOK, false},
		{"admin", p3, args{okAdmin}, http.StatusOK, false},
		{"no-email", p3, args{noEmail}, http.StatusOK, false},
		{"bad-token", p3, args{"foobar"}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.prov.AuthorizeSign(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
				assert.Nil(t, got)
			} else if assert.NotNil(t, got) {
				assert.Equals(t, 8, len(got))
				for _, o := range got {
					switch v := o.(type) {
					case *OIDC:
					case certificateOptionsFunc:
					case *provisionerExtensionOption:
						assert.Equals(t, v.Type, TypeOIDC)
						assert.Equals(t, v.Name, tt.prov.GetName())
						assert.Equals(t, v.CredentialID, tt.prov.ClientID)
						assert.Len(t, 0, v.KeyValuePairs)
					case profileDefaultDuration:
						assert.Equals(t, time.Duration(v), tt.prov.ctl.Claimer.DefaultTLSCertDuration())
					case defaultPublicKeyValidator:
					case *validityValidator:
						assert.Equals(t, v.min, tt.prov.ctl.Claimer.MinTLSCertDuration())
						assert.Equals(t, v.max, tt.prov.ctl.Claimer.MaxTLSCertDuration())
					case emailOnlyIdentity:
						assert.Equals(t, string(v), "name@smallstep.com")
					case *x509NamePolicyValidator:
						assert.Equals(t, nil, v.policyEngine)
					case *WebhookController:
						assert.Len(t, 0, v.webhooks)
					default:
						assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
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
		code    int
		wantErr bool
	}{
		{"ok1", p1, args{t1}, http.StatusUnauthorized, true},
		{"admin", p3, args{okAdmin}, http.StatusOK, false},
		{"fail-email", p3, args{failEmail}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.prov.AuthorizeRevoke(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				fmt.Println(tt)
				t.Errorf("OIDC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			}
		})
	}
}

func TestOIDC_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p1, err := generateOIDC()
	assert.FatalError(t, err)
	p2, err := generateOIDC()
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.ctl.Claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		code    int
		wantErr bool
	}{
		{"ok", p1, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusOK, false},
		{"fail/renew-disabled", p2, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.prov.AuthorizeRenew(context.Background(), tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			} else if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			}
		})
	}
}

func TestOIDC_AuthorizeSSHSign(t *testing.T) {
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
	p4, err := generateOIDC()
	assert.FatalError(t, err)
	p5, err := generateOIDC()
	assert.FatalError(t, err)
	p6, err := generateOIDC()
	assert.FatalError(t, err)
	// Admin + Domains
	p3.Admins = []string{"name@smallstep.com", "root@example.com"}
	p3.Domains = []string{"smallstep.com"}
	// disable sshCA
	disable := false
	p6.Claims = &Claims{EnableSSHCA: &disable}
	p6.ctl.Claimer, err = NewClaimer(p6.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	// Update configuration endpoints and initialize
	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p2.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p3.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p4.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p5.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))
	assert.FatalError(t, p2.Init(config))
	assert.FatalError(t, p3.Init(config))
	assert.FatalError(t, p4.Init(config))
	assert.FatalError(t, p5.Init(config))

	p4.ctl.IdentityFunc = func(ctx context.Context, p Interface, email string) (*Identity, error) {
		return &Identity{Usernames: []string{"max", "mariano"}}, nil
	}
	p5.ctl.IdentityFunc = func(ctx context.Context, p Interface, email string) (*Identity, error) {
		return nil, errors.New("force")
	}
	// Additional test needed for empty usernames and duplicate email and usernames

	t1, err := generateSimpleToken("the-issuer", p1.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	okGetIdentityToken, err := generateSimpleToken("the-issuer", p4.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	failGetIdentityToken, err := generateSimpleToken("the-issuer", p5.ClientID, &keys.Keys[0])
	assert.FatalError(t, err)
	// Admin email not in domains
	okAdmin, err := generateOIDCToken("subject", "the-issuer", p3.ClientID, "root@example.com", "", time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Empty email
	emptyEmail, err := generateToken("subject", "the-issuer", p1.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
	expectemptyEmailOptions := &SignSSHOptions{
		CertType:   "user",
		Principals: []string{},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(p1.ctl.Claimer.DefaultUserSSHCertDuration())),
	}
	assert.FatalError(t, err)

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	pub := key.Public().Key
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)
	//nolint:gosec // tests minimum size of the key
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.FatalError(t, err)

	userDuration := p1.ctl.Claimer.DefaultUserSSHCertDuration()
	hostDuration := p1.ctl.Claimer.DefaultHostSSHCertDuration()
	expectedUserOptions := &SignSSHOptions{
		CertType: "user", Principals: []string{"name", "name@smallstep.com"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration)),
	}
	expectedAdminOptions := &SignSSHOptions{
		CertType: "user", Principals: []string{"root", "root@example.com"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration)),
	}
	expectedHostOptions := &SignSSHOptions{
		CertType: "host", Principals: []string{"smallstep.com"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SignSSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		prov        *OIDC
		args        args
		expected    *SignSSHOptions
		code        int
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SignSSHOptions{}, pub}, expectedUserOptions, http.StatusOK, false, false},
		{"ok-rsa2048", p1, args{t1, SignSSHOptions{}, rsa2048.Public()}, expectedUserOptions, http.StatusOK, false, false},
		{"ok-user", p1, args{t1, SignSSHOptions{CertType: "user"}, pub}, expectedUserOptions, http.StatusOK, false, false},
		{"ok-empty-email", p1, args{emptyEmail, SignSSHOptions{CertType: "user"}, pub}, expectemptyEmailOptions, http.StatusOK, false, false},
		{"ok-principals", p1, args{t1, SignSSHOptions{Principals: []string{"name"}}, pub},
			&SignSSHOptions{CertType: "user", Principals: []string{"name", "name@smallstep.com"},
				ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration))}, http.StatusOK, false, false},
		{"ok-principals-getIdentity", p4, args{okGetIdentityToken, SignSSHOptions{Principals: []string{"mariano"}}, pub},
			&SignSSHOptions{CertType: "user", Principals: []string{"max", "mariano"},
				ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration))}, http.StatusOK, false, false},
		{"ok-emptyPrincipals-getIdentity", p4, args{okGetIdentityToken, SignSSHOptions{}, pub},
			&SignSSHOptions{CertType: "user", Principals: []string{"max", "mariano"},
				ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration))}, http.StatusOK, false, false},
		{"ok-options", p1, args{t1, SignSSHOptions{CertType: "user", Principals: []string{"name"}}, pub},
			&SignSSHOptions{CertType: "user", Principals: []string{"name", "name@smallstep.com"},
				ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration))}, http.StatusOK, false, false},
		{"ok-admin-user", p3, args{okAdmin, SignSSHOptions{CertType: "user", KeyID: "root@example.com", Principals: []string{"root", "root@example.com"}}, pub},
			expectedAdminOptions, http.StatusOK, false, false},
		{"ok-admin-host", p3, args{okAdmin, SignSSHOptions{CertType: "host", KeyID: "smallstep.com", Principals: []string{"smallstep.com"}}, pub},
			expectedHostOptions, http.StatusOK, false, false},
		{"ok-admin-options", p3, args{okAdmin, SignSSHOptions{CertType: "user", KeyID: "name", Principals: []string{"name"}}, pub},
			&SignSSHOptions{CertType: "user", Principals: []string{"name"},
				ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(userDuration))}, http.StatusOK, false, false},
		{"fail-rsa1024", p1, args{t1, SignSSHOptions{}, rsa1024.Public()}, expectedUserOptions, http.StatusOK, false, true},
		{"fail-user-host", p1, args{t1, SignSSHOptions{CertType: "host"}, pub}, nil, http.StatusOK, false, true},
		{"fail-user-principals", p1, args{t1, SignSSHOptions{Principals: []string{"root"}}, pub}, nil, http.StatusOK, false, true},
		{"fail-getIdentity", p5, args{failGetIdentityToken, SignSSHOptions{}, pub}, nil, http.StatusInternalServerError, true, false},
		{"fail-sshCA-disabled", p6, args{"foo", SignSSHOptions{}, pub}, nil, http.StatusUnauthorized, true, false},
		// Missing parametrs
		{"fail-admin-type", p3, args{okAdmin, SignSSHOptions{KeyID: "root@example.com", Principals: []string{"root@example.com"}}, pub}, nil, http.StatusUnauthorized, false, true},
		{"fail-admin-key-id", p3, args{okAdmin, SignSSHOptions{CertType: "user", Principals: []string{"root@example.com"}}, pub}, nil, http.StatusUnauthorized, false, true},
		{"fail-admin-principals", p3, args{okAdmin, SignSSHOptions{CertType: "user", KeyID: "root@example.com"}, pub}, nil, http.StatusUnauthorized, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.prov.AuthorizeSSHSign(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.AuthorizeSSHSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
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

func TestOIDC_AuthorizeSSHRevoke(t *testing.T) {
	p1, err := generateOIDC()
	assert.FatalError(t, err)
	p2, err := generateOIDC()
	assert.FatalError(t, err)
	p2.Admins = []string{"root@example.com"}

	srv := generateJWKServer(2)
	defer srv.Close()
	var keys jose.JSONWebKeySet
	assert.FatalError(t, getAndDecode(srv.URL+"/private", &keys))

	config := Config{Claims: globalProvisionerClaims}
	p1.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	p2.ConfigurationEndpoint = srv.URL + "/.well-known/openid-configuration"
	assert.FatalError(t, p1.Init(config))
	assert.FatalError(t, p2.Init(config))

	// Invalid email
	failEmail, err := generateToken("subject", "the-issuer", p1.ClientID, "", []string{}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Admin email not in domains
	noAdmin, err := generateToken("subject", "the-issuer", p1.ClientID, "root@example.com", []string{"test.smallstep.com"}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)
	// Admin email in domains
	okAdmin, err := generateToken("subject", "the-issuer", p2.ClientID, "root@example.com", []string{"test.smallstep.com"}, time.Now(), &keys.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *OIDC
		args    args
		code    int
		wantErr bool
	}{
		{"ok", p2, args{okAdmin}, http.StatusOK, false},
		{"fail/invalid-token", p1, args{failEmail}, http.StatusUnauthorized, true},
		{"fail/not-admin", p1, args{noAdmin}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.prov.AuthorizeSSHRevoke(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.AuthorizeSSHRevoke() error = %v, wantErr %v", err, tt.wantErr)
			} else if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
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

func Test_openIDPayload_IsAdmin(t *testing.T) {
	type fields struct {
		Email  string
		Groups []string
	}
	type args struct {
		admins []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"ok email", fields{"admin@smallstep.com", nil}, args{[]string{"admin@smallstep.com"}}, true},
		{"ok email multiple", fields{"admin@smallstep.com", []string{"admin", "eng"}}, args{[]string{"eng@smallstep.com", "admin@smallstep.com"}}, true},
		{"ok email sanitized", fields{"admin@Smallstep.com", nil}, args{[]string{"admin@smallStep.com"}}, true},
		{"ok group", fields{"", []string{"admin"}}, args{[]string{"admin"}}, true},
		{"ok group multiple", fields{"admin@smallstep.com", []string{"engineering", "admin"}}, args{[]string{"admin"}}, true},
		{"fail missing", fields{"eng@smallstep.com", []string{"admin"}}, args{[]string{"admin@smallstep.com"}}, false},
		{"fail email letter case", fields{"Admin@smallstep.com", []string{}}, args{[]string{"admin@smallstep.com"}}, false},
		{"fail group letter case", fields{"", []string{"Admin"}}, args{[]string{"admin"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &openIDPayload{
				Email:  tt.fields.Email,
				Groups: tt.fields.Groups,
			}
			if got := o.IsAdmin(tt.args.admins); got != tt.want {
				t.Errorf("openIDPayload.IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}
