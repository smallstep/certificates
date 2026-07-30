package authority

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

func TestGetEncryptedKey(t *testing.T) {
	type ek struct {
		a    *Authority
		kid  string
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *ek{
		"ok": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			require.NoError(t, err)
			a, err := New(c)
			require.NoError(t, err)
			return &ek{
				a:   a,
				kid: c.AuthorityConfig.Provisioners[1].(*provisioner.JWK).Key.KeyID,
			}
		},
		"fail-not-found": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			require.NoError(t, err)
			a, err := New(c)
			require.NoError(t, err)
			return &ek{
				a:    a,
				kid:  "foo",
				err:  errors.New("encrypted key with kid foo was not found"),
				code: http.StatusNotFound,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ek, err := tc.a.GetEncryptedKey(tc.kid)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					val, ok := tc.a.provisioners.Load("mike:" + tc.kid)
					assert.Fatal(t, ok)
					p, ok := val.(*provisioner.JWK)
					assert.Fatal(t, ok)
					assert.Equals(t, p.EncryptedKey, ek)
				}
			}
		})
	}
}

type mockAdminDB struct {
	admin.MockDB
	MGetCertificateData func(string) (*db.CertificateData, error)
}

func (c *mockAdminDB) GetCertificateData(sn string) (*db.CertificateData, error) {
	return c.MGetCertificateData(sn)
}

func TestGetProvisioners(t *testing.T) {
	type gp struct {
		a    *Authority
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *gp{
		"ok": func(t *testing.T) *gp {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			require.NoError(t, err)
			a, err := New(c)
			require.NoError(t, err)
			return &gp{a: a}
		},
		"ok/rsa": func(t *testing.T) *gp {
			c, err := LoadConfiguration("../ca/testdata/rsaca.json")
			require.NoError(t, err)
			a, err := New(c)
			require.NoError(t, err)
			return &gp{a: a}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ps, next, err := tc.a.GetProvisioners("", 0)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, tc.code, sc.StatusCode())
					}
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.a.config.AuthorityConfig.Provisioners, ps)
					assert.Equals(t, "", next)
				}
			}
		})
	}
}

func TestAuthority_LoadProvisionerByCertificate(t *testing.T) {
	_, priv, err := keyutil.GenerateDefaultKeyPair()
	require.NoError(t, err)
	csr := getCSR(t, priv)

	sign := func(a *Authority, extraOpts ...provisioner.SignOption) *x509.Certificate {
		key, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
		require.NoError(t, err)
		token, err := generateToken("smallstep test", "step-cli", testAudiences.Sign[0], []string{"test.smallstep.com"}, time.Now(), key)
		require.NoError(t, err)
		ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
		opts, err := a.Authorize(ctx, token)
		require.NoError(t, err)
		opts = append(opts, extraOpts...)
		certs, err := a.SignWithContext(ctx, csr, provisioner.SignOptions{}, opts...)
		require.NoError(t, err)
		return certs[0]
	}
	getProvisioner := func(a *Authority, name string) provisioner.Interface {
		p, ok := a.provisioners.LoadByName(name)
		if !ok {
			t.Fatalf("provisioner %s does not exists", name)
		}
		return p
	}
	removeExtension := provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		for i, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(provisioner.StepOIDProvisioner) {
				cert.ExtraExtensions = append(cert.ExtraExtensions[:i], cert.ExtraExtensions[i+1:]...)
				break
			}
		}
		return nil
	})

	a0 := testAuthority(t)

	a1 := testAuthority(t)
	a1.db = &db.MockAuthDB{
		MUseToken: func(id, tok string) (bool, error) {
			return true, nil
		},
		MGetCertificateData: func(serialNumber string) (*db.CertificateData, error) {
			p, err := a1.LoadProvisionerByName("dev")
			require.NoError(t, err)
			return &db.CertificateData{
				Provisioner: &db.ProvisionerData{
					ID:   p.GetID(),
					Name: p.GetName(),
					Type: p.GetType().String(),
				},
			}, nil
		},
	}

	a2 := testAuthority(t)
	a2.adminDB = &mockAdminDB{
		MGetCertificateData: (func(s string) (*db.CertificateData, error) {
			p, err := a2.LoadProvisionerByName("dev")
			require.NoError(t, err)
			return &db.CertificateData{
				Provisioner: &db.ProvisionerData{
					ID:   p.GetID(),
					Name: p.GetName(),
					Type: p.GetType().String(),
				},
			}, nil
		}),
	}

	a3 := testAuthority(t)
	a3.db = &db.MockAuthDB{
		MUseToken: func(id, tok string) (bool, error) {
			return true, nil
		},
		MGetCertificateData: func(serialNumber string) (*db.CertificateData, error) {
			return &db.CertificateData{
				Provisioner: &db.ProvisionerData{
					ID: "foo", Name: "foo", Type: "foo",
				},
			}, nil
		},
	}

	a4 := testAuthority(t)
	a4.adminDB = &mockAdminDB{
		MGetCertificateData: func(serialNumber string) (*db.CertificateData, error) {
			return &db.CertificateData{
				Provisioner: &db.ProvisionerData{
					ID: "foo", Name: "foo", Type: "foo",
				},
			}, nil
		},
	}

	type args struct {
		crt *x509.Certificate
	}
	tests := []struct {
		name      string
		authority *Authority
		args      args
		want      provisioner.Interface
		wantErr   bool
	}{
		{"ok from certificate", a0, args{sign(a0)}, getProvisioner(a0, "step-cli"), false},
		{"ok from db", a1, args{sign(a1)}, getProvisioner(a1, "dev"), false},
		{"ok from admindb", a2, args{sign(a2)}, getProvisioner(a2, "dev"), false},
		{"fail from certificate", a0, args{sign(a0, removeExtension)}, nil, true},
		{"fail from db", a3, args{sign(a3, removeExtension)}, nil, true},
		{"fail from admindb", a4, args{sign(a4, removeExtension)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.authority.LoadProvisionerByCertificate(tt.args.crt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.LoadProvisionerByCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.LoadProvisionerByCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvisionerWebhookToLinkedca(t *testing.T) {
	type test struct {
		lwh *linkedca.Webhook
		pwh *provisioner.Webhook
	}
	tests := map[string]test{
		"empty": test{
			lwh: &linkedca.Webhook{},
			pwh: &provisioner.Webhook{Kind: "NO_KIND", CertType: "ALL"},
		},
		"enriching ssh basic auth": test{
			lwh: &linkedca.Webhook{
				Id:     "abc123",
				Name:   "people",
				Url:    "https://localhost",
				Kind:   linkedca.Webhook_ENRICHING,
				Secret: "secret",
				Auth: &linkedca.Webhook_BasicAuth{
					BasicAuth: &linkedca.BasicAuth{
						Username: "user",
						Password: "pass",
					},
				},
				DisableTlsClientAuth: true,
				CertType:             linkedca.Webhook_SSH,
			},
			pwh: &provisioner.Webhook{
				ID:     "abc123",
				Name:   "people",
				URL:    "https://localhost",
				Kind:   "ENRICHING",
				Secret: "secret",
				BasicAuth: struct {
					Username string
					Password string
				}{
					Username: "user",
					Password: "pass",
				},
				DisableTLSClientAuth: true,
				CertType:             "SSH",
			},
		},
		"authorizing x509 bearer auth": test{
			lwh: &linkedca.Webhook{
				Id:     "abc123",
				Name:   "people",
				Url:    "https://localhost",
				Kind:   linkedca.Webhook_AUTHORIZING,
				Secret: "secret",
				Auth: &linkedca.Webhook_BearerToken{
					BearerToken: &linkedca.BearerToken{
						BearerToken: "tkn",
					},
				},
				CertType: linkedca.Webhook_X509,
			},
			pwh: &provisioner.Webhook{
				ID:          "abc123",
				Name:        "people",
				URL:         "https://localhost",
				Kind:        "AUTHORIZING",
				Secret:      "secret",
				BearerToken: "tkn",
				CertType:    "X509",
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotLWH := provisionerWebhookToLinkedca(test.pwh)
			assert.Equals(t, test.lwh, gotLWH)

			gotPWH := webhookToCertificates(test.lwh)
			assert.Equals(t, test.pwh, gotPWH)
		})
	}
}

func TestProvisionerTypeFromDetails(t *testing.T) {
	tests := map[string]struct {
		details *linkedca.ProvisionerDetails
		want    linkedca.Provisioner_Type
		wantErr bool
	}{
		"jwk":             {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_JWK{JWK: &linkedca.JWKProvisioner{}}}, want: linkedca.Provisioner_JWK},
		"oidc":            {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_OIDC{OIDC: &linkedca.OIDCProvisioner{}}}, want: linkedca.Provisioner_OIDC},
		"gcp":             {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_GCP{GCP: &linkedca.GCPProvisioner{}}}, want: linkedca.Provisioner_GCP},
		"aws":             {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_AWS{AWS: &linkedca.AWSProvisioner{}}}, want: linkedca.Provisioner_AWS},
		"azure":           {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_Azure{Azure: &linkedca.AzureProvisioner{}}}, want: linkedca.Provisioner_AZURE},
		"acme":            {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{ACME: &linkedca.ACMEProvisioner{}}}, want: linkedca.Provisioner_ACME},
		"x5c":             {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_X5C{X5C: &linkedca.X5CProvisioner{}}}, want: linkedca.Provisioner_X5C},
		"k8ssa":           {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_K8SSA{K8SSA: &linkedca.K8SSAProvisioner{}}}, want: linkedca.Provisioner_K8SSA},
		"sshpop":          {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_SSHPOP{SSHPOP: &linkedca.SSHPOPProvisioner{}}}, want: linkedca.Provisioner_SSHPOP},
		"scep":            {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_SCEP{SCEP: &linkedca.SCEPProvisioner{}}}, want: linkedca.Provisioner_SCEP},
		"nebula":          {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_Nebula{Nebula: &linkedca.NebulaProvisioner{}}}, want: linkedca.Provisioner_NEBULA},
		"nil details":     {wantErr: true},
		"missing oneof":   {details: &linkedca.ProvisionerDetails{}, wantErr: true},
		"nil oneof value": {details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_AWS{}}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := provisionerTypeFromDetails(tc.details)
			if tc.wantErr {
				if err == nil {
					t.Fatal("provisionerTypeFromDetails() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("provisionerTypeFromDetails() error = %v", err)
			}
			assert.Equals(t, tc.want, got)
		})
	}
}

func TestProvisionerToCertificates_typeDetailsMismatch(t *testing.T) {
	p := &linkedca.Provisioner{
		Name: "mismatch",
		Type: linkedca.Provisioner_JWK,
		Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{
			ACME: &linkedca.ACMEProvisioner{},
		}},
	}

	if _, err := ProvisionerToCertificates(p); err == nil {
		t.Fatal("ProvisionerToCertificates() error = nil, want type/details mismatch")
	}
}

func Test_wrapRAProvisioner(t *testing.T) {
	type args struct {
		p      provisioner.Interface
		raInfo *provisioner.RAInfo
	}
	tests := []struct {
		name string
		args args
		want *wrappedProvisioner
	}{
		{"ok", args{&provisioner.JWK{Name: "jwt"}, &provisioner.RAInfo{ProvisionerName: "ra"}}, &wrappedProvisioner{
			Interface: &provisioner.JWK{Name: "jwt"},
			raInfo:    &provisioner.RAInfo{ProvisionerName: "ra"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wrapRAProvisioner(tt.args.p, tt.args.raInfo); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wrapRAProvisioner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isRAProvisioner(t *testing.T) {
	type args struct {
		p provisioner.Interface
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"true", args{&wrappedProvisioner{
			Interface: &provisioner.JWK{Name: "jwt"},
			raInfo:    &provisioner.RAInfo{ProvisionerName: "ra"},
		}}, true},
		{"nil ra", args{&wrappedProvisioner{
			Interface: &provisioner.JWK{Name: "jwt"},
		}}, false},
		{"not ra", args{&provisioner.JWK{Name: "jwt"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRAProvisioner(tt.args.p); got != tt.want {
				t.Errorf("isRAProvisioner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_ProvisionerConversionErrorsAreBadRequests(t *testing.T) {
	methods := map[string]func(*Authority, *linkedca.Provisioner) error{
		"store": func(a *Authority, p *linkedca.Provisioner) error {
			return a.StoreProvisioner(context.Background(), p)
		},
		"update": func(a *Authority, p *linkedca.Provisioner) error {
			return a.UpdateProvisioner(context.Background(), p)
		},
	}

	for name, method := range methods {
		t.Run(name, func(t *testing.T) {
			a := testAuthority(t)
			p := &linkedca.Provisioner{
				Name: "mismatch",
				Type: linkedca.Provisioner_JWK,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{
					ACME: &linkedca.ACMEProvisioner{},
				}},
			}

			err := method(a, p)
			var adminErr *admin.Error
			if !errors.As(err, &adminErr) {
				t.Fatalf("expected *admin.Error, got %T: %v", err, err)
			}
			assert.Equals(t, admin.ErrorBadRequestType.String(), adminErr.Type)
			assert.Equals(t, http.StatusBadRequest, adminErr.Status)
		})
	}
}

func TestAuthority_UpdateProvisioner_invalidConfiguration(t *testing.T) {
	a := testAuthority(t)
	// ClientId is empty, so provisioner.OIDC.Init fails before any I/O or
	// DB access; the error must surface as a 400, not a 500.
	nu := &linkedca.Provisioner{
		Name: "bad-oidc",
		Type: linkedca.Provisioner_OIDC,
		Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_OIDC{
			OIDC: &linkedca.OIDCProvisioner{ConfigurationEndpoint: "https://example.com"},
		}},
	}
	err := a.UpdateProvisioner(context.Background(), nu)
	var adminErr *admin.Error
	if !errors.As(err, &adminErr) {
		t.Fatalf("expected *admin.Error, got %T: %v", err, err)
	}
	assert.Equals(t, admin.ErrorBadRequestType.String(), adminErr.Type)
	assert.Equals(t, 400, adminErr.Status)
}
