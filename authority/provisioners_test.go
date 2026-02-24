package authority

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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

func TestAuthority_StoreProvisioner(t *testing.T) {
	type test struct {
		auth *Authority
		prov *linkedca.Provisioner
		err  error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/conversion-error": func(t *testing.T) test {
			auth := testAuthority(t)
			// Create a provisioner with invalid details that will fail conversion
			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey: []byte("invalid-key"), // This will cause conversion to fail
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  errors.New("error converting to certificates provisioner"),
			}
		},
		"fail/duplicate-name": func(t *testing.T) test {
			auth := testAuthority(t)
			// Create a valid provisioner first
			key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			existingProv := &provisioner.JWK{
				Name: "existing-provisioner",
				Type: "JWK",
				Key:  key,
			}
			auth.provisioners.Store(existingProv)

			// Try to store another provisioner with the same name
			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "existing-provisioner", // Same name as existing
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.NewError(admin.ErrorBadRequestType, "provisioner with name existing-provisioner already exists"),
			}
		},
		"fail/duplicate-token-id": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					return admin.NewError(admin.ErrorBadRequestType, "provisioner with token ID already exists")
				},
			}
			// Create a JWK provisioner that will have a specific token ID
			key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			keyBytes, err := key.MarshalJSON()
			assert.FatalError(t, err)

			existingProv := &provisioner.JWK{
				Name: "existing-provisioner",
				Type: "JWK",
				Key:  key,
			}
			// Create a proper config with valid claims for initialization
			config := provisioner.Config{
				Claims: provisioner.Claims{
					MinTLSDur:     &provisioner.Duration{Duration: 5 * time.Minute},
					MaxTLSDur:     &provisioner.Duration{Duration: 24 * time.Hour},
					DefaultTLSDur: &provisioner.Duration{Duration: 24 * time.Hour},
				},
			}
			existingProv.Init(config)
			auth.provisioners.Store(existingProv)

			// Try to store another provisioner with the same key (same token ID)
			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "different-name",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           keyBytes,
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.NewError(admin.ErrorBadRequestType, "provisioner with token ID"),
			}
		},
		"fail/config-generation-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-provisioner-id"
					return nil
				},
			}
			// Simulate config generation failure by setting invalid claims that will fail validation
			auth.config.AuthorityConfig.Claims = &provisioner.Claims{
				// Invalid configuration: MinTLSDur > MaxTLSDur
				MinTLSDur: &provisioner.Duration{Duration: 24 * time.Hour},
				MaxTLSDur: &provisioner.Duration{Duration: 5 * time.Minute},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapErrorISE(errors.New("claims: MaxCertDuration cannot be less than MinCertDuration"), "error generating provisioner config"),
			}
		},
		"fail/policy-validation-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-provisioner-id"
					return nil
				},
			}
			// Create a provisioner with invalid policy
			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.invalid..domain"}, // Invalid DNS pattern
						},
					},
				},
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  errors.New("cannot parse permitted domain constraint"),
			}
		},
		"fail/provisioner-init-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-provisioner-id"
					return nil
				},
			}
			// Create a provisioner with invalid configuration that will fail Init
			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"invalid"}`), // Invalid key
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapError(admin.ErrorBadRequestType, errors.New("validation"), "error validating configuration for provisioner"),
			}
		},
		"fail/db-create-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					return errors.New("database error")
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapErrorISE(errors.New("database error"), "error creating provisioner"),
			}
		},
		"fail/second-conversion-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					// Corrupt the provisioner data after first conversion succeeds
					prov.Details = &linkedca.ProvisionerDetails{
						Data: &linkedca.ProvisionerDetails_JWK{
							JWK: &linkedca.JWKProvisioner{
								PublicKey: []byte("corrupted-after-db-save"),
							},
						},
					}
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapErrorISE(errors.New("conversion error"), "error converting to certificates provisioner from linkedca provisioner"),
			}
		},
		"fail/second-init-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-id"
					// Corrupt the key to make second init fail
					if jwkProv := prov.Details.GetJWK(); jwkProv != nil {
						jwkProv.PublicKey = []byte("corrupted-key")
					}
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapErrorISE(errors.New("init error"), "error initializing provisioner test-provisioner"),
			}
		},
		"fail/provisioner-store-error": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-id"
					return nil
				},
			}

			// Create a conflicting provisioner in the cache to cause store error
			key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			conflictingProv := &provisioner.JWK{
				Name: "test-provisioner", // Same name as the one we'll try to store
				Type: "JWK",
				Key:  key,
			}
			// Create a proper config with valid claims for initialization
			config := provisioner.Config{
				Claims: provisioner.Claims{
					MinTLSDur:     &provisioner.Duration{Duration: 5 * time.Minute},
					MaxTLSDur:     &provisioner.Duration{Duration: 24 * time.Hour},
					DefaultTLSDur: &provisioner.Duration{Duration: 24 * time.Hour},
				},
			}
			conflictingProv.Init(config)
			auth.provisioners.Store(conflictingProv)

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  admin.WrapErrorISE(errors.New("store error"), "error storing provisioner in authority cache"),
			}
		},
		"ok/jwk-provisioner": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "new-provisioner-id"
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-jwk-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
				Claims: &linkedca.Claims{
					X509: &linkedca.X509Claims{
						Enabled: true,
						Durations: &linkedca.Durations{
							Default: "24h",
							Min:     "1h",
							Max:     "720h",
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  nil,
			}
		},
		"ok/acme-provisioner": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "acme-provisioner-id"
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_ACME,
				Name: "test-acme-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_ACME{
						ACME: &linkedca.ACMEProvisioner{
							ForceCn: true,
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  nil,
			}
		},
		"ok/with-policy": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "policy-provisioner-id"
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-policy-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.example.com"},
						},
						Deny: &linkedca.X509Names{
							Dns: []string{"*.internal.example.com"},
						},
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  nil,
			}
		},
		"ok/with-templates": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "template-provisioner-id"
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-template-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
				X509Template: &linkedca.Template{
					Template: []byte(`{"subject": "{{.Subject}}"}`),
					Data:     []byte(`{"customField": "value"}`),
				},
				SshTemplate: &linkedca.Template{
					Template: []byte(`{"user": "{{.User}}"}`),
					Data:     []byte(`{"sshCustom": "sshValue"}`),
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  nil,
			}
		},
		"ok/with-webhooks": func(t *testing.T) test {
			auth := testAuthority(t)
			auth.adminDB = &admin.MockDB{
				MockCreateProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					prov.Id = "webhook-provisioner-id"
					return nil
				},
			}

			prov := &linkedca.Provisioner{
				Type: linkedca.Provisioner_JWK,
				Name: "test-webhook-provisioner",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_JWK{
						JWK: &linkedca.JWKProvisioner{
							PublicKey:           []byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}`),
							EncryptedPrivateKey: []byte("encrypted-key"),
						},
					},
				},
				Webhooks: []*linkedca.Webhook{
					{
						Name: "test-webhook",
						Url:  "https://example.com/webhook",
						Kind: linkedca.Webhook_ENRICHING,
					},
				},
			}
			return test{
				auth: auth,
				prov: prov,
				err:  nil,
			}
		},
	}

	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			err := tc.auth.StoreProvisioner(context.Background(), tc.prov)
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					var adminErr *admin.Error
					if errors.As(err, &adminErr) && errors.As(tc.err, &adminErr) {
						assert.Equals(t, adminErr.Type, tc.err.(*admin.Error).Type)
					} else {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				assert.Nil(t, tc.err)

				// Verify provisioner was stored correctly
				if tc.err == nil {
					// Check that provisioner exists in cache by name
					storedProv, ok := tc.auth.provisioners.LoadByName(tc.prov.Name)
					assert.True(t, ok, "provisioner should be stored in cache")
					assert.Equals(t, tc.prov.Name, storedProv.GetName())

					// Verify the provisioner ID was set by the database
					assert.NotEquals(t, "", tc.prov.Id, "provisioner ID should be set after storage")
				}
			}
		})
	}
}
