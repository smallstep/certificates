package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

func testAuthority(t *testing.T, opts ...Option) *Authority {
	maxjwk, err := jose.ReadKey("testdata/secrets/max_pub.jwk")
	assert.FatalError(t, err)
	clijwk, err := jose.ReadKey("testdata/secrets/step_cli_key_pub.jwk")
	assert.FatalError(t, err)
	disableRenewal := true
	enableSSHCA := true
	p := provisioner.List{
		&provisioner.JWK{
			Name: "Max",
			Type: "JWK",
			Key:  maxjwk,
		},
		&provisioner.JWK{
			Name: "step-cli",
			Type: "JWK",
			Key:  clijwk,
			Claims: &provisioner.Claims{
				EnableSSHCA: &enableSSHCA,
			},
		},
		&provisioner.JWK{
			Name: "dev",
			Type: "JWK",
			Key:  maxjwk,
			Claims: &provisioner.Claims{
				DisableRenewal: &disableRenewal,
			},
		},
		&provisioner.JWK{
			Name: "renew_disabled",
			Type: "JWK",
			Key:  maxjwk,
			Claims: &provisioner.Claims{
				DisableRenewal: &disableRenewal,
			},
		},
		&provisioner.SSHPOP{
			Name: "sshpop",
			Type: "SSHPOP",
			Claims: &provisioner.Claims{
				EnableSSHCA: &enableSSHCA,
			},
		},
	}
	c := &Config{
		Address:          "127.0.0.1:443",
		Root:             []string{"testdata/certs/root_ca.crt"},
		IntermediateCert: "testdata/certs/intermediate_ca.crt",
		IntermediateKey:  "testdata/secrets/intermediate_ca_key",
		SSH: &SSHConfig{
			HostKey: "testdata/secrets/ssh_host_ca_key",
			UserKey: "testdata/secrets/ssh_user_ca_key",
		},
		DNSNames: []string{"example.com"},
		Password: "pass",
		AuthorityConfig: &AuthConfig{
			Provisioners: p,
		},
	}
	a, err := New(c, opts...)
	assert.FatalError(t, err)
	// Avoid errors when test tokens are created before the test authority. This
	// happens in some tests where we re-create the same authority to test
	// special cases without re-creating the token.
	a.startTime = a.startTime.Add(-1 * time.Minute)
	return a
}

func TestAuthorityNew(t *testing.T) {
	type newTest struct {
		config *Config
		err    error
	}
	tests := map[string]func(t *testing.T) *newTest{
		"ok": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			return &newTest{
				config: c,
			}
		},
		"fail bad root": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.Root = []string{"foo"}
			return &newTest{
				config: c,
				err:    errors.New("error reading foo: no such file or directory"),
			}
		},
		"fail bad password": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.Password = "wrong"
			return &newTest{
				config: c,
				err:    errors.New("error decrypting ../ca/testdata/secrets/intermediate_ca_key: x509: decryption password incorrect"),
			}
		},
		"fail loading CA cert": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.IntermediateCert = "wrong"
			return &newTest{
				config: c,
				err:    errors.New("error reading wrong: no such file or directory"),
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			auth, err := New(tc.config)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					sum := sha256.Sum256(auth.rootX509Certs[0].Raw)
					root, ok := auth.certificates.Load(hex.EncodeToString(sum[:]))
					assert.Fatal(t, ok)
					assert.Equals(t, auth.rootX509Certs[0], root)

					assert.True(t, auth.initOnce)
					assert.NotNil(t, auth.x509CAService)
					for _, p := range tc.config.AuthorityConfig.Provisioners {
						var _p provisioner.Interface
						_p, ok = auth.provisioners.Load(p.GetID())
						assert.True(t, ok)
						assert.Equals(t, p, _p)
						var kid, encryptedKey string
						if kid, encryptedKey, ok = p.GetEncryptedKey(); ok {
							var key string
							key, ok = auth.provisioners.LoadEncryptedKey(kid)
							assert.True(t, ok)
							assert.Equals(t, encryptedKey, key)
						}
					}
					// sanity check
					_, ok = auth.provisioners.Load("fooo")
					assert.False(t, ok)
				}
			}
		})
	}
}

func TestAuthorityNew_bundles(t *testing.T) {
	ca0, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	ca1, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}

	rootPath := t.TempDir()
	writeCert := func(fn string, certs ...*x509.Certificate) error {
		var b []byte
		for _, crt := range certs {
			b = append(b, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt.Raw,
			})...)
		}
		return os.WriteFile(filepath.Join(rootPath, fn), b, 0600)
	}
	writeKey := func(fn string, signer crypto.Signer) error {
		_, err := pemutil.Serialize(signer, pemutil.ToFile(filepath.Join(rootPath, fn), 0600))
		return err
	}

	if err := writeCert("root0.crt", ca0.Root); err != nil {
		t.Fatal(err)
	}
	if err := writeCert("int0.crt", ca0.Intermediate); err != nil {
		t.Fatal(err)
	}
	if err := writeKey("int0.key", ca0.Signer); err != nil {
		t.Fatal(err)
	}
	if err := writeCert("root1.crt", ca1.Root); err != nil {
		t.Fatal(err)
	}
	if err := writeCert("int1.crt", ca1.Intermediate); err != nil {
		t.Fatal(err)
	}
	if err := writeKey("int1.key", ca1.Signer); err != nil {
		t.Fatal(err)
	}
	if err := writeCert("bundle0.crt", ca0.Root, ca1.Root); err != nil {
		t.Fatal(err)
	}
	if err := writeCert("bundle1.crt", ca1.Root, ca2.Root); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{"ok ca0", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "root0.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, false},
		{"ok bundle", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "bundle0.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, false},
		{"ok federated ca1", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "root0.crt")},
			FederatedRoots:   []string{filepath.Join(rootPath, "root1.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, false},
		{"ok federated bundle", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "root0.crt")},
			FederatedRoots:   []string{filepath.Join(rootPath, "bundle1.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, false},
		{"fail root", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "missing.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, true},
		{"fail federated", &config.Config{
			Address:          "127.0.0.1:443",
			Root:             []string{filepath.Join(rootPath, "root0.crt")},
			FederatedRoots:   []string{filepath.Join(rootPath, "missing.crt")},
			IntermediateCert: filepath.Join(rootPath, "int0.crt"),
			IntermediateKey:  filepath.Join(rootPath, "int0.key"),
			DNSNames:         []string{"127.0.0.1"},
			AuthorityConfig:  &AuthConfig{},
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAuthority_GetDatabase(t *testing.T) {
	auth := testAuthority(t)
	authWithDatabase, err := New(auth.config, WithDatabase(auth.db))
	assert.FatalError(t, err)

	tests := []struct {
		name string
		auth *Authority
		want db.AuthDB
	}{
		{"ok", auth, auth.db},
		{"ok WithDatabase", authWithDatabase, auth.db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.auth.GetDatabase(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetDatabase() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewEmbedded(t *testing.T) {
	caPEM, err := os.ReadFile("testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	crt, err := pemutil.ReadCertificate("testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	key, err := pemutil.Read("testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	type args struct {
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{[]Option{WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer))}}, false},
		{"ok empty config", args{[]Option{WithConfig(&Config{}), WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer))}}, false},
		{"ok config file", args{[]Option{WithConfigFile("../ca/testdata/ca.json")}}, false},
		{"ok config", args{[]Option{WithConfig(&Config{
			Root:             []string{"testdata/certs/root_ca.crt"},
			IntermediateCert: "testdata/certs/intermediate_ca.crt",
			IntermediateKey:  "testdata/secrets/intermediate_ca_key",
			Password:         "pass",
			AuthorityConfig:  &AuthConfig{},
		})}}, false},
		{"fail options", args{[]Option{WithX509RootBundle([]byte("bad data"))}}, true},
		{"fail missing config", args{[]Option{WithConfig(nil), WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer))}}, true},
		{"fail missing root", args{[]Option{WithX509Signer(crt, key.(crypto.Signer))}}, true},
		{"fail missing signer", args{[]Option{WithX509RootBundle(caPEM)}}, true},
		{"fail missing root file", args{[]Option{WithConfig(&Config{
			IntermediateCert: "testdata/certs/intermediate_ca.crt",
			IntermediateKey:  "testdata/secrets/intermediate_ca_key",
			Password:         "pass",
			AuthorityConfig:  &AuthConfig{},
		})}}, true},
		{"fail missing issuer", args{[]Option{WithConfig(&Config{
			Root:            []string{"testdata/certs/root_ca.crt"},
			IntermediateKey: "testdata/secrets/intermediate_ca_key",
			Password:        "pass",
			AuthorityConfig: &AuthConfig{},
		})}}, true},
		{"fail missing signer", args{[]Option{WithConfig(&Config{
			Root:             []string{"testdata/certs/root_ca.crt"},
			IntermediateCert: "testdata/certs/intermediate_ca.crt",
			Password:         "pass",
			AuthorityConfig:  &AuthConfig{},
		})}}, true},
		{"fail bad password", args{[]Option{WithConfig(&Config{
			Root:             []string{"testdata/certs/root_ca.crt"},
			IntermediateCert: "testdata/certs/intermediate_ca.crt",
			IntermediateKey:  "testdata/secrets/intermediate_ca_key",
			Password:         "bad",
			AuthorityConfig:  &AuthConfig{},
		})}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEmbedded(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEmbedded() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				assert.True(t, got.initOnce)
				assert.NotNil(t, got.rootX509Certs)
				assert.NotNil(t, got.x509CAService)
			}
		})
	}
}

func TestNewEmbedded_Sign(t *testing.T) {
	caPEM, err := os.ReadFile("testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	crt, err := pemutil.ReadCertificate("testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	key, err := pemutil.Read("testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	a, err := NewEmbedded(WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer)))
	assert.FatalError(t, err)

	// Sign
	cr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"foo.bar.zar"},
	}, key)
	assert.FatalError(t, err)
	csr, err := x509.ParseCertificateRequest(cr)
	assert.FatalError(t, err)

	cert, err := a.Sign(csr, provisioner.SignOptions{})
	assert.FatalError(t, err)
	assert.Equals(t, []string{"foo.bar.zar"}, cert[0].DNSNames)
	assert.Equals(t, crt, cert[1])
}

func TestNewEmbedded_GetTLSCertificate(t *testing.T) {
	caPEM, err := os.ReadFile("testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	crt, err := pemutil.ReadCertificate("testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	key, err := pemutil.Read("testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	a, err := NewEmbedded(WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer)))
	assert.FatalError(t, err)

	// GetTLSCertificate
	cert, err := a.GetTLSCertificate()
	assert.FatalError(t, err)
	assert.Equals(t, []string{"localhost"}, cert.Leaf.DNSNames)
	assert.True(t, cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	assert.True(t, cert.Leaf.IPAddresses[1].Equal(net.ParseIP("::1")))
}

func TestAuthority_CloseForReload(t *testing.T) {
	tests := []struct {
		name string
		auth *Authority
	}{
		{"ok", testAuthority(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.auth.CloseForReload()
		})
	}
}

func testScepAuthority(t *testing.T, opts ...Option) *Authority {
	p := provisioner.List{
		&provisioner.SCEP{
			Name: "scep1",
			Type: "SCEP",
		},
	}
	c := &Config{
		Address:          "127.0.0.1:8443",
		InsecureAddress:  "127.0.0.1:8080",
		Root:             []string{"testdata/scep/root.crt"},
		IntermediateCert: "testdata/scep/intermediate.crt",
		IntermediateKey:  "testdata/scep/intermediate.key",
		DNSNames:         []string{"example.com"},
		Password:         "pass",
		AuthorityConfig: &AuthConfig{
			Provisioners: p,
		},
	}
	a, err := New(c, opts...)
	assert.FatalError(t, err)
	return a
}

func TestAuthority_GetSCEPService(t *testing.T) {
	_ = testScepAuthority(t)
	p := provisioner.List{
		&provisioner.SCEP{
			Name: "scep1",
			Type: "SCEP",
		},
	}
	type fields struct {
		config *Config
	}
	tests := []struct {
		name        string
		fields      fields
		wantService bool
		wantErr     bool
	}{
		{
			name: "ok",
			fields: fields{
				config: &Config{
					Address:          "127.0.0.1:8443",
					InsecureAddress:  "127.0.0.1:8080",
					Root:             []string{"testdata/scep/root.crt"},
					IntermediateCert: "testdata/scep/intermediate.crt",
					IntermediateKey:  "testdata/scep/intermediate.key",
					DNSNames:         []string{"example.com"},
					Password:         "pass",
					AuthorityConfig: &AuthConfig{
						Provisioners: p,
					},
				},
			},
			wantService: true,
			wantErr:     false,
		},
		{
			name: "wrong password",
			fields: fields{
				config: &Config{
					Address:          "127.0.0.1:8443",
					InsecureAddress:  "127.0.0.1:8080",
					Root:             []string{"testdata/scep/root.crt"},
					IntermediateCert: "testdata/scep/intermediate.crt",
					IntermediateKey:  "testdata/scep/intermediate.key",
					DNSNames:         []string{"example.com"},
					Password:         "wrongpass",
					AuthorityConfig: &AuthConfig{
						Provisioners: p,
					},
				},
			},
			wantService: false,
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(tt.fields.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.New(), error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantService {
				if got := a.GetSCEPService(); (got != nil) != tt.wantService {
					t.Errorf("Authority.GetSCEPService() = %v, wantService %v", got, tt.wantService)
				}
			}
		})
	}
}

func TestAuthority_GetID(t *testing.T) {
	type fields struct {
		authorityID string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{""}, "00000000-0000-0000-0000-000000000000"},
		{"ok with id", fields{"10b9a431-ed3b-4a5f-abee-ec35119b65e7"}, "10b9a431-ed3b-4a5f-abee-ec35119b65e7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						AuthorityID: tt.fields.authorityID,
					},
				},
			}
			if got := a.GetID(); got != tt.want {
				t.Errorf("Authority.GetID() = %v, want %v", got, tt.want)
			}
		})
	}
}
