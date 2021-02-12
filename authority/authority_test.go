package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io/ioutil"
	"net"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/jose"
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
	caPEM, err := ioutil.ReadFile("testdata/certs/root_ca.crt")
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
	caPEM, err := ioutil.ReadFile("testdata/certs/root_ca.crt")
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
	caPEM, err := ioutil.ReadFile("testdata/certs/root_ca.crt")
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
