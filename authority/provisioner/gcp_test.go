package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestGCP_Getters(t *testing.T) {
	p, err := generateGCP()
	assert.FatalError(t, err)
	id := "gcp/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("GCP.GetID() = %v, want %v", got, id)
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

	aud := "https://ca.smallstep.com/1.0/sign#" + url.QueryEscape(id)
	expected := fmt.Sprintf("http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s&format=full&licenses=FALSE", url.QueryEscape(aud))
	if got := p.GetIdentityURL(aud); got != expected {
		t.Errorf("GCP.GetIdentityURL() = %v, want %v", got, expected)
	}
}

func TestGCP_GetTokenID(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)
	p1.Name = "name"

	p2, err := generateGCP()
	assert.FatalError(t, err)
	p2.DisableTrustOnFirstUse = true

	now := time.Now()
	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", "gcp/name",
		"instance-id", "instance-name", "project-id", "zone",
		now, &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	t2, err := generateGCPToken(p2.ServiceAccounts[0],
		"https://accounts.google.com", p2.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		now, &p2.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	sum := sha256.Sum256([]byte("gcp/name.instance-id"))
	want1 := strings.ToLower(hex.EncodeToString(sum[:]))
	sum = sha256.Sum256([]byte(t2))
	want2 := strings.ToLower(hex.EncodeToString(sum[:]))

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
		{"ok", p1, args{t1}, want1, false},
		{"ok", p2, args{t2}, want2, false},
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

	type args struct {
		subject string
		caURL   string
	}
	tests := []struct {
		name        string
		gcp         *GCP
		args        args
		identityURL string
		want        string
		wantErr     bool
	}{
		{"ok", p1, args{"subject", "https://ca"}, srv.URL, t1, false},
		{"fail ca url", p1, args{"subject", "://ca"}, srv.URL, "", true},
		{"fail request", p1, args{"subject", "https://ca"}, srv.URL + "/bad-request", "", true},
		{"fail url", p1, args{"subject", "https://ca"}, "://ca.smallstep.com", "", true},
		{"fail connect", p1, args{"subject", "https://ca"}, "foobarzar", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.gcp.config.IdentityURL = tt.identityURL
			got, err := tt.gcp.GetIdentityToken(tt.args.subject, tt.args.caURL)
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

	config := Config{
		Claims: globalProvisionerClaims,
	}
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}
	zero := Duration{Duration: 0}
	type fields struct {
		Type            string
		Name            string
		ServiceAccounts []string
		InstanceAge     Duration
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
		{"ok", fields{"GCP", "name", nil, zero, nil}, args{config, srv.URL}, false},
		{"ok", fields{"GCP", "name", []string{"service-account"}, zero, nil}, args{config, srv.URL}, false},
		{"ok", fields{"GCP", "name", []string{"service-account"}, Duration{Duration: 1 * time.Minute}, nil}, args{config, srv.URL}, false},
		{"bad type", fields{"", "name", nil, zero, nil}, args{config, srv.URL}, true},
		{"bad name", fields{"GCP", "", nil, zero, nil}, args{config, srv.URL}, true},
		{"bad duration", fields{"GCP", "name", nil, Duration{Duration: -1 * time.Minute}, nil}, args{config, srv.URL}, true},
		{"bad claims", fields{"GCP", "name", nil, zero, badClaims}, args{config, srv.URL}, true},
		{"bad certs", fields{"GCP", "name", nil, zero, nil}, args{config, srv.URL + "/error"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &GCP{
				Type:            tt.fields.Type,
				Name:            tt.fields.Name,
				ServiceAccounts: tt.fields.ServiceAccounts,
				InstanceAge:     tt.fields.InstanceAge,
				Claims:          tt.fields.Claims,
				config: &gcpConfig{
					CertsURL:    tt.args.certsURL,
					IdentityURL: gcpIdentityURL,
				},
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("GCP.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGCP_authorizeToken(t *testing.T) {
	type test struct {
		p     *GCP
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; error parsing gcp token"),
			}
		},
		"fail/cannot-validate-sig": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now(), jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; failed to validate gcp token payload - cannot find key for kid "),
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://foo.bar.zap", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; invalid gcp token payload"),
			}
		},
		"fail/invalid-serviceAccount": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken("foo",
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; invalid gcp token - invalid subject claim"),
			}
		},
		"fail/invalid-projectID": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			p.ProjectIDs = []string{"foo", "bar"}
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; invalid gcp token - invalid project id"),
			}
		},
		"fail/instance-age": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			p.InstanceAge = Duration{1 * time.Minute}
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now().Add(-1*time.Minute), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; token google.compute_engine.instance_creation_timestamp is too old"),
			}
		},
		"fail/empty-instance-id": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"", "instance-name", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; gcp token google.compute_engine.instance_id cannot be empty"),
			}
		},
		"fail/empty-instance-name": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; gcp token google.compute_engine.instance_name cannot be empty"),
			}
		},
		"fail/empty-project-id": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; gcp token google.compute_engine.project_id cannot be empty"),
			}
		},
		"fail/empty-zone": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "",
				time.Now(), &p.keyStore.keySet.Keys[0])
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("gcp.authorizeToken; gcp token google.compute_engine.zone cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateGCP()
			assert.FatalError(t, err)
			tok, err := generateGCPToken(p.ServiceAccounts[0],
				"https://accounts.google.com", p.GetID(),
				"instance-id", "instance-name", "project-id", "zone",
				time.Now(), &p.keyStore.keySet.Keys[0])
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
			if claims, err := tc.p.authorizeToken(tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) && assert.NotNil(t, claims) {
					assert.Equals(t, claims.Subject, tc.p.ServiceAccounts[0])
					assert.Equals(t, claims.Issuer, "https://accounts.google.com")
					assert.NotNil(t, claims.Google)

					aud, err := generateSignAudience("https://ca.smallstep.com", tc.p.GetID())
					assert.FatalError(t, err)
					assert.Equals(t, claims.Audience[0], aud)
				}
			}
		})
	}
}

func TestGCP_AuthorizeSign(t *testing.T) {
	p1, err := generateGCP()
	assert.FatalError(t, err)

	p2, err := generateGCP()
	assert.FatalError(t, err)
	p2.DisableCustomSANs = true

	p3, err := generateGCP()
	assert.FatalError(t, err)
	p3.ProjectIDs = []string{"other-project-id"}
	p3.ServiceAccounts = []string{"foo@developer.gserviceaccount.com"}
	p3.InstanceAge = Duration{1 * time.Minute}

	aKey, err := generateJSONWebKey()
	assert.FatalError(t, err)

	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	t2, err := generateGCPToken(p2.ServiceAccounts[0],
		"https://accounts.google.com", p2.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p2.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	t3, err := generateGCPToken(p3.ServiceAccounts[0],
		"https://accounts.google.com", p3.GetID(),
		"instance-id", "instance-name", "other-project-id", "zone",
		time.Now(), &p3.keyStore.keySet.Keys[0])
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
	assert.FatalError(t, err)
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
	failInvalidProjectID, err := generateGCPToken(p3.ServiceAccounts[0],
		"https://accounts.google.com", p3.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p3.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)
	failInvalidInstanceAge, err := generateGCPToken(p3.ServiceAccounts[0],
		"https://accounts.google.com", p3.GetID(),
		"instance-id", "instance-name", "other-project-id", "zone",
		time.Now().Add(-1*time.Minute), &p3.keyStore.keySet.Keys[0])
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
		wantLen int
		code    int
		wantErr bool
	}{
		{"ok", p1, args{t1}, 8, http.StatusOK, false},
		{"ok", p2, args{t2}, 13, http.StatusOK, false},
		{"ok", p3, args{t3}, 8, http.StatusOK, false},
		{"fail token", p1, args{"token"}, 0, http.StatusUnauthorized, true},
		{"fail key", p1, args{failKey}, 0, http.StatusUnauthorized, true},
		{"fail iss", p1, args{failIss}, 0, http.StatusUnauthorized, true},
		{"fail aud", p1, args{failAud}, 0, http.StatusUnauthorized, true},
		{"fail exp", p1, args{failExp}, 0, http.StatusUnauthorized, true},
		{"fail nbf", p1, args{failNbf}, 0, http.StatusUnauthorized, true},
		{"fail service account", p1, args{failServiceAccount}, 0, http.StatusUnauthorized, true},
		{"fail invalid project id", p3, args{failInvalidProjectID}, 0, http.StatusUnauthorized, true},
		{"fail invalid instance age", p3, args{failInvalidInstanceAge}, 0, http.StatusUnauthorized, true},
		{"fail instance id", p1, args{failInstanceID}, 0, http.StatusUnauthorized, true},
		{"fail instance name", p1, args{failInstanceName}, 0, http.StatusUnauthorized, true},
		{"fail project id", p1, args{failProjectID}, 0, http.StatusUnauthorized, true},
		{"fail zone", p1, args{failZone}, 0, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			switch got, err := tt.gcp.AuthorizeSign(ctx, tt.args.token); {
			case (err != nil) != tt.wantErr:
				t.Errorf("GCP.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			case err != nil:
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			default:
				assert.Equals(t, tt.wantLen, len(got))
				for _, o := range got {
					switch v := o.(type) {
					case *GCP:
					case certificateOptionsFunc:
					case *provisionerExtensionOption:
						assert.Equals(t, v.Type, TypeGCP)
						assert.Equals(t, v.Name, tt.gcp.GetName())
						assert.Equals(t, v.CredentialID, tt.gcp.ServiceAccounts[0])
						assert.Len(t, 4, v.KeyValuePairs)
					case profileDefaultDuration:
						assert.Equals(t, time.Duration(v), tt.gcp.ctl.Claimer.DefaultTLSCertDuration())
					case commonNameSliceValidator:
						assert.Equals(t, []string(v), []string{"instance-name", "instance-id", "instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal"})
					case defaultPublicKeyValidator:
					case *validityValidator:
						assert.Equals(t, v.min, tt.gcp.ctl.Claimer.MinTLSCertDuration())
						assert.Equals(t, v.max, tt.gcp.ctl.Claimer.MaxTLSCertDuration())
					case ipAddressesValidator:
						assert.Equals(t, v, nil)
					case emailAddressesValidator:
						assert.Equals(t, v, nil)
					case urisValidator:
						assert.Equals(t, v, nil)
					case dnsNamesValidator:
						assert.Equals(t, []string(v), []string{"instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal"})
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

func TestGCP_AuthorizeSSHSign(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	p1, err := generateGCP()
	assert.FatalError(t, err)
	p1.DisableCustomSANs = true

	p2, err := generateGCP()
	assert.FatalError(t, err)
	p2.DisableCustomSANs = false

	p3, err := generateGCP()
	assert.FatalError(t, err)
	// disable sshCA
	disable := false
	p3.Claims = &Claims{EnableSSHCA: &disable}
	p3.ctl.Claimer, err = NewClaimer(p3.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	t1, err := generateGCPToken(p1.ServiceAccounts[0],
		"https://accounts.google.com", p1.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p1.keyStore.keySet.Keys[0])
	assert.FatalError(t, err)

	t2, err := generateGCPToken(p2.ServiceAccounts[0],
		"https://accounts.google.com", p2.GetID(),
		"instance-id", "instance-name", "project-id", "zone",
		time.Now(), &p2.keyStore.keySet.Keys[0])
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

	hostDuration := p1.ctl.Claimer.DefaultHostSSHCertDuration()
	expectedHostOptions := &SignSSHOptions{
		CertType: "host", Principals: []string{"instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsPrincipal1 := &SignSSHOptions{
		CertType: "host", Principals: []string{"instance-name.c.project-id.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsPrincipal2 := &SignSSHOptions{
		CertType: "host", Principals: []string{"instance-name.zone.c.project-id.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedCustomOptions := &SignSSHOptions{
		CertType: "host", Principals: []string{"foo.bar", "bar.foo"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SignSSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		gcp         *GCP
		args        args
		expected    *SignSSHOptions
		code        int
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SignSSHOptions{}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-rsa2048", p1, args{t1, SignSSHOptions{}, rsa2048.Public()}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-type", p1, args{t1, SignSSHOptions{CertType: "host"}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-principals", p1, args{t1, SignSSHOptions{Principals: []string{"instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal"}}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-principal1", p1, args{t1, SignSSHOptions{Principals: []string{"instance-name.c.project-id.internal"}}, pub}, expectedHostOptionsPrincipal1, http.StatusOK, false, false},
		{"ok-principal2", p1, args{t1, SignSSHOptions{Principals: []string{"instance-name.zone.c.project-id.internal"}}, pub}, expectedHostOptionsPrincipal2, http.StatusOK, false, false},
		{"ok-options", p1, args{t1, SignSSHOptions{CertType: "host", Principals: []string{"instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal"}}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-custom", p2, args{t2, SignSSHOptions{Principals: []string{"foo.bar", "bar.foo"}}, pub}, expectedCustomOptions, http.StatusOK, false, false},
		{"fail-rsa1024", p1, args{t1, SignSSHOptions{}, rsa1024.Public()}, expectedHostOptions, http.StatusOK, false, true},
		{"fail-type", p1, args{t1, SignSSHOptions{CertType: "user"}, pub}, nil, http.StatusOK, false, true},
		{"fail-principal", p1, args{t1, SignSSHOptions{Principals: []string{"smallstep.com"}}, pub}, nil, http.StatusOK, false, true},
		{"fail-extra-principal", p1, args{t1, SignSSHOptions{Principals: []string{"instance-name.c.project-id.internal", "instance-name.zone.c.project-id.internal", "smallstep.com"}}, pub}, nil, http.StatusOK, false, true},
		{"fail-sshCA-disabled", p3, args{"foo", SignSSHOptions{}, pub}, expectedHostOptions, http.StatusUnauthorized, true, false},
		{"fail-invalid-token", p1, args{"foo", SignSSHOptions{}, pub}, expectedHostOptions, http.StatusUnauthorized, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.gcp.AuthorizeSSHSign(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("GCP.AuthorizeSSHSign() error = %v, wantErr %v", err, tt.wantErr)
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

func TestGCP_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p1, err := generateGCP()
	assert.FatalError(t, err)
	p2, err := generateGCP()
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
		prov    *GCP
		args    args
		code    int
		wantErr bool
	}{
		{"ok", p1, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusOK, false},
		{"fail/renewal-disabled", p2, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenew(context.Background(), tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("GCP.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			} else if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			}
		})
	}
}
