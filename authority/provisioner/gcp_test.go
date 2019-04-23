package provisioner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func resetGoogleVars() {
	gcpCertsURL = "https://www.googleapis.com/oauth2/v3/certs"
	gcpIdentityURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
}

func TestGCP_Getters(t *testing.T) {
	p, err := generateGCP()
	assert.FatalError(t, err)
	aud := "gcp:" + p.Name
	if got := p.GetID(); got != aud {
		t.Errorf("GCP.GetID() = %v, want %v", got, aud)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("GCP.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeGCP {
		t.Errorf("GCP.GetType() = %v, want %v", got, TypeGCP)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("GCP.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
	expected := fmt.Sprintf("http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s&format=full&licenses=FALSE", url.QueryEscape(p.GetID()))
	if got := p.GetIdentityURL(); got != expected {
		t.Errorf("GCP.GetIdentityURL() = %v, want %v", got, expected)
	}
}

func TestGCP_GetTokenID(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)
	p1.Name = "name"

	now := time.Now()
	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", "gcp:name",
		"instance-id", "instance-name", "project-id", "zone",
		now, &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	unique := fmt.Sprintf("gcp:name.instance-id.%d.%d", now.Unix(), now.Add(5*time.Minute).Unix())
	sum := sha256.Sum256([]byte(unique))
	want := strings.ToLower(hex.EncodeToString(sum[:]))

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		gcp     *GCP
		args    args
		want    string
		wantErr bool
	}{
		{"ok", p1, args{t1}, want, false},
		{"fail token", p1, args{"token"}, "", true},
		{"fail claims", p1, args{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey.fooo"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.gcp.GetTokenID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("GCP.GetTokenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GCP.GetTokenID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGCP_GetIdentityToken(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)
	defer resetGoogleVars()

	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad-request":
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		default:
			w.Write([]byte(t1))
		}
	}))
	defer srv.Close()

	tests := []struct {
		name        string
		gcp         *GCP
		identityURL string
		want        string
		wantErr     bool
	}{
		{"ok", p1, srv.URL, t1, false},
		{"fail request", p1, srv.URL + "/bad-request", "", true},
		{"fail url", p1, "://ca.smallstep.com", "", true},
		{"fail connect", p1, "foobarzar", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gcpIdentityURL = tt.identityURL
			got, err := tt.gcp.GetIdentityToken()
			t.Log(err)
			if (err != nil) != tt.wantErr {
				t.Errorf("GCP.GetIdentityToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GCP.GetIdentityToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGCP_Init(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()
	defer resetGoogleVars()

	config := Config{
		Claims: globalProvisionerClaims,
	}
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}

	type fields struct {
		Type            string
		Name            string
		ServiceAccounts []string
		Claims          *Claims
	}
	type args struct {
		config   Config
		certsURL string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{"GCP", "name", nil, nil}, args{config, srv.URL}, false},
		{"ok", fields{"GCP", "name", []string{"service-account"}, nil}, args{config, srv.URL}, false},
		{"bad type", fields{"", "name", nil, nil}, args{config, srv.URL}, true},
		{"bad name", fields{"GCP", "", nil, nil}, args{config, srv.URL}, true},
		{"bad claims", fields{"GCP", "name", nil, badClaims}, args{config, srv.URL}, true},
		{"bad certs", fields{"GCP", "name", nil, nil}, args{config, srv.URL + "/error"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gcpCertsURL = tt.args.certsURL
			p := &GCP{
				Type:            tt.fields.Type,
				Name:            tt.fields.Name,
				ServiceAccounts: tt.fields.ServiceAccounts,
				Claims:          tt.fields.Claims,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("GCP.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGCP_AuthorizeSign(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)

	aKey, err := generateJSONWebKey()
	assert.FatalError(t, err)

	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failKey, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), aKey)
	assert.FatalError(t, err)
	failIss, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://foo.bar.zar", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	failAud, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", "gcp:foo",
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failExp, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now().Add(-360*time.Second), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failNbf, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now().Add(360*time.Second), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failServiceAccount, err := generateGCPToken("foo",
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failInstanceID, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failInstanceName, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failProjectID, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failZone, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		gcp     *GCP
		args    args
		wantErr bool
	}{
		{"ok", p1, args{t1}, false},
		{"fail token", p1, args{"token"}, true},
		{"fail key", p1, args{failKey}, true},
		{"fail iss", p1, args{failIss}, true},
		{"fail aud", p1, args{failAud}, true},
		{"fail exp", p1, args{failExp}, true},
		{"fail nbf", p1, args{failNbf}, true},
		{"fail service account", p1, args{failServiceAccount}, true},
		{"fail instance id", p1, args{failInstanceID}, true},
		{"fail instance name", p1, args{failInstanceName}, true},
		{"fail project id", p1, args{failProjectID}, true},
		{"fail zone", p1, args{failZone}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.gcp.AuthorizeSign(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("GCP.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				assert.Len(t, 5, got)
			}
		})
	}
}

func TestGCP_AuthorizeRenewal(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)
	p2, err := generateGCP()
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
		prov    *GCP
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("GCP.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGCP_AuthorizeRevoke(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)

	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		gcp     *GCP
		args    args
		wantErr bool
	}{
		{"ok", p1, args{t1}, true}, // revoke is disabled
		{"fail", p1, args{"token"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.gcp.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("GCP.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
