package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func TestAzure_Getters(t *testing.T) {
	p, err := generateAzure()
	assert.FatalError(t, err)
	if got := p.GetID(); got != p.TenantID {
		t.Errorf("Azure.GetID() = %v, want %v", got, p.TenantID)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("Azure.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeAzure {
		t.Errorf("Azure.GetType() = %v, want %v", got, TypeAzure)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("Azure.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestAzure_GetTokenID(t *testing.T) {
	p1, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	p2, err := generateAzure()
	assert.FatalError(t, err)
	p2.TenantID = p1.TenantID
	p2.config = p1.config
	p2.oidcConfig = p1.oidcConfig
	p2.keyStore = p1.keyStore
	p2.DisableTrustOnFirstUse = true

	t1, err := p1.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)
	t2, err := p2.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)

	sum := sha256.Sum256([]byte("/subscriptions/subscriptionID/resourceGroups/resourceGroup/providers/Microsoft.Compute/virtualMachines/virtualMachine"))
	w1 := strings.ToLower(hex.EncodeToString(sum[:]))

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		azure   *Azure
		args    args
		want    string
		wantErr bool
	}{
		{"ok", p1, args{t1}, w1, false},
		{"ok no TOFU", p2, args{t2}, "the-jti", false},
		{"fail token", p1, args{"bad-token"}, "", true},
		{"fail claims", p1, args{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey.fooo"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.azure.GetTokenID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.GetTokenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Azure.GetTokenID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAzure_GetIdentityToken(t *testing.T) {
	p1, err := generateAzure()
	assert.FatalError(t, err)

	t1, err := generateAzureToken("subject", p1.oidcConfig.Issuer, azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad-request":
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		case "/bad-json":
			w.Write([]byte(t1))
		default:
			w.Header().Add("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{"access_token":"%s"}`, t1)))
		}
	}))
	defer srv.Close()

	type args struct {
		subject string
		caURL   string
	}
	tests := []struct {
		name             string
		azure            *Azure
		args             args
		identityTokenURL string
		want             string
		wantErr          bool
	}{
		{"ok", p1, args{"subject", "caURL"}, srv.URL, t1, false},
		{"fail request", p1, args{"subject", "caURL"}, srv.URL + "/bad-request", "", true},
		{"fail unmarshal", p1, args{"subject", "caURL"}, srv.URL + "/bad-json", "", true},
		{"fail url", p1, args{"subject", "caURL"}, "://ca.smallstep.com", "", true},
		{"fail connect", p1, args{"subject", "caURL"}, "foobarzar", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.azure.config.identityTokenURL = tt.identityTokenURL
			got, err := tt.azure.GetIdentityToken(tt.args.subject, tt.args.caURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.GetIdentityToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Azure.GetIdentityToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAzure_Init(t *testing.T) {
	p1, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	config := Config{
		Claims: globalProvisionerClaims,
	}
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}

	badDiscoveryURL := &azureConfig{
		oidcDiscoveryURL: srv.URL + "/error",
		identityTokenURL: p1.config.identityTokenURL,
	}
	badJWKURL := &azureConfig{
		oidcDiscoveryURL: srv.URL + "/openid-configuration-fail-jwk",
		identityTokenURL: p1.config.identityTokenURL,
	}
	badAzureConfig := &azureConfig{
		oidcDiscoveryURL: srv.URL + "/openid-configuration-no-issuer",
		identityTokenURL: p1.config.identityTokenURL,
	}

	type fields struct {
		Type     string
		Name     string
		TenantID string
		Claims   *Claims
		config   *azureConfig
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
		{"ok", fields{p1.Type, p1.Name, p1.TenantID, nil, p1.config}, args{config}, false},
		{"ok with config", fields{p1.Type, p1.Name, p1.TenantID, nil, p1.config}, args{config}, false},
		{"fail type", fields{"", p1.Name, p1.TenantID, nil, p1.config}, args{config}, true},
		{"fail name", fields{p1.Type, "", p1.TenantID, nil, p1.config}, args{config}, true},
		{"fail tenant id", fields{p1.Type, p1.Name, "", nil, p1.config}, args{config}, true},
		{"fail claims", fields{p1.Type, p1.Name, p1.TenantID, badClaims, p1.config}, args{config}, true},
		{"fail discovery URL", fields{p1.Type, p1.Name, p1.TenantID, nil, badDiscoveryURL}, args{config}, true},
		{"fail JWK URL", fields{p1.Type, p1.Name, p1.TenantID, nil, badJWKURL}, args{config}, true},
		{"fail config Validate", fields{p1.Type, p1.Name, p1.TenantID, nil, badAzureConfig}, args{config}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Azure{
				Type:     tt.fields.Type,
				Name:     tt.fields.Name,
				TenantID: tt.fields.TenantID,
				Claims:   tt.fields.Claims,
				config:   tt.fields.config,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("Azure.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAzure_AuthorizeSign(t *testing.T) {
	p1, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	p2, err := generateAzure()
	assert.FatalError(t, err)
	p2.TenantID = p1.TenantID
	p2.ResourceGroups = []string{"resourceGroup"}
	p2.config = p1.config
	p2.oidcConfig = p1.oidcConfig
	p2.keyStore = p1.keyStore
	p2.DisableCustomSANs = true

	p3, err := generateAzure()
	assert.FatalError(t, err)
	p3.config = p1.config
	p3.oidcConfig = p1.oidcConfig
	p3.keyStore = p1.keyStore

	p4, err := generateAzure()
	assert.FatalError(t, err)
	p4.TenantID = p1.TenantID
	p4.ResourceGroups = []string{"foobarzar"}
	p4.config = p1.config
	p4.oidcConfig = p1.oidcConfig
	p4.keyStore = p1.keyStore

	badKey, err := generateJSONWebKey()
	assert.FatalError(t, err)

	t1, err := p1.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)
	t2, err := p2.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)
	t3, err := p3.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)
	t4, err := p4.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)

	t11, err := generateAzureToken("subject", p1.oidcConfig.Issuer, azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	failIssuer, err := generateAzureToken("subject", "bad-issuer", azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failAudience, err := generateAzureToken("subject", p1.oidcConfig.Issuer, "bad-audience",
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failExp, err := generateAzureToken("subject", p1.oidcConfig.Issuer, azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now().Add(-360*time.Second), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failNbf, err := generateAzureToken("subject", p1.oidcConfig.Issuer, azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now().Add(360*time.Second), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failKey, err := generateAzureToken("subject", p1.oidcConfig.Issuer, azureDefaultAudience,
		p1.TenantID, "subscriptionID", "resourceGroup", "virtualMachine",
		time.Now(), badKey)
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		azure   *Azure
		args    args
		wantLen int
		wantErr bool
	}{
		{"ok", p1, args{t1}, 4, false},
		{"ok", p2, args{t2}, 6, false},
		{"ok", p1, args{t11}, 4, false},
		{"fail tenant", p3, args{t3}, 0, true},
		{"fail resource group", p4, args{t4}, 0, true},
		{"fail token", p1, args{"token"}, 0, true},
		{"fail issuer", p1, args{failIssuer}, 0, true},
		{"fail audience", p1, args{failAudience}, 0, true},
		{"fail exp", p1, args{failExp}, 0, true},
		{"fail nbf", p1, args{failNbf}, 0, true},
		{"fail key", p1, args{failKey}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			got, err := tt.azure.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Len(t, tt.wantLen, got)
		})
	}
}

func TestAzure_AuthorizeSign_SSH(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	p1, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	t1, err := p1.GetIdentityToken("subject", "caURL")
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

	hostDuration := p1.claimer.DefaultHostSSHCertDuration()
	expectedHostOptions := &SSHOptions{
		CertType: "host", Principals: []string{"virtualMachine"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		azure       *Azure
		args        args
		expected    *SSHOptions
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SSHOptions{}, pub}, expectedHostOptions, false, false},
		{"ok-rsa2048", p1, args{t1, SSHOptions{}, rsa2048.Public()}, expectedHostOptions, false, false},
		{"ok-type", p1, args{t1, SSHOptions{CertType: "host"}, pub}, expectedHostOptions, false, false},
		{"ok-principals", p1, args{t1, SSHOptions{Principals: []string{"virtualMachine"}}, pub}, expectedHostOptions, false, false},
		{"ok-options", p1, args{t1, SSHOptions{CertType: "host", Principals: []string{"virtualMachine"}}, pub}, expectedHostOptions, false, false},
		{"fail-rsa1024", p1, args{t1, SSHOptions{}, rsa1024.Public()}, expectedHostOptions, false, true},
		{"fail-type", p1, args{t1, SSHOptions{CertType: "user"}, pub}, nil, false, true},
		{"fail-principal", p1, args{t1, SSHOptions{Principals: []string{"smallstep.com"}}, pub}, nil, false, true},
		{"fail-extra-principal", p1, args{t1, SSHOptions{Principals: []string{"virtualMachine", "smallstep.com"}}, pub}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignSSHMethod)
			got, err := tt.azure.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
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

func TestAzure_AuthorizeRenewal(t *testing.T) {
	p1, err := generateAzure()
	assert.FatalError(t, err)
	p2, err := generateAzure()
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
		azure   *Azure
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.azure.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAzure_AuthorizeRevoke(t *testing.T) {
	az, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	token, err := az.GetIdentityToken("subject", "caURL")
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		azure   *Azure
		args    args
		wantErr bool
	}{
		{"ok token", az, args{token}, true}, // revoke is disabled
		{"bad token", az, args{"bad token"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.azure.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAzure_assertConfig(t *testing.T) {
	p1, err := generateAzure()
	assert.FatalError(t, err)
	p2, err := generateAzure()
	assert.FatalError(t, err)
	p2.config = nil

	tests := []struct {
		name  string
		azure *Azure
	}{
		{"ok with config", p1},
		{"ok no config", p2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.azure.assertConfig()
		})
	}
}
