package config

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	_ "github.com/smallstep/certificates/cas"
	"go.step.sm/crypto/jose"
)

func TestConfigValidate(t *testing.T) {
	maxjwk, err := jose.ReadKey("../testdata/secrets/max_pub.jwk")
	assert.FatalError(t, err)
	clijwk, err := jose.ReadKey("../testdata/secrets/step_cli_key_pub.jwk")
	assert.FatalError(t, err)
	ac := &AuthConfig{
		Provisioners: provisioner.List{
			&provisioner.JWK{
				Name: "Max",
				Type: "JWK",
				Key:  maxjwk,
			},
			&provisioner.JWK{
				Name: "step-cli",
				Type: "JWK",
				Key:  clijwk,
			},
		},
	}

	type ConfigValidateTest struct {
		config *Config
		err    error
		tls    *TLSOptions
	}
	tests := map[string]func(*testing.T) ConfigValidateTest{
		"skip-validation": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					SkipValidation: true,
				},
			}
		},
		"empty-address": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				err: errors.New("address cannot be empty"),
			}
		},
		"invalid-address": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				err: errors.New("invalid address 127.0.0.1"),
			}
		},
		"empty-root": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				err: errors.New("root cannot be empty"),
			}
		},
		"empty-intermediate-cert": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:         "127.0.0.1:443",
					Root:            []string{"../testdata/secrets/root_ca.crt"},
					IntermediateKey: "../testdata/secrets/intermediate_ca_key",
					DNSNames:        []string{"test.smallstep.com"},
					Password:        "pass",
					AuthorityConfig: ac,
				},
				err: errors.New("crt cannot be empty"),
			}
		},
		"empty-intermediate-key": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				err: errors.New("key cannot be empty"),
			}
		},
		"empty-dnsNames": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				err: errors.New("dnsNames cannot be empty"),
			}
		},
		"empty-TLS": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
				},
				tls: &DefaultTLSOptions,
			}
		},
		"empty-TLS-values": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
					TLS:              &TLSOptions{},
				},
				tls: &DefaultTLSOptions,
			}
		},
		"custom-tls-values": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
					TLS: &TLSOptions{
						CipherSuites: CipherSuites{
							"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
						},
						MinVersion:    1.0,
						MaxVersion:    1.1,
						Renegotiation: true,
					},
				},
				tls: &TLSOptions{
					CipherSuites: CipherSuites{
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
					},
					MinVersion:    1.0,
					MaxVersion:    1.1,
					Renegotiation: true,
				},
			}
		},
		"tls-min>max": func(t *testing.T) ConfigValidateTest {
			return ConfigValidateTest{
				config: &Config{
					Address:          "127.0.0.1:443",
					Root:             []string{"../testdata/secrets/root_ca.crt"},
					IntermediateCert: "../testdata/secrets/intermediate_ca.crt",
					IntermediateKey:  "../testdata/secrets/intermediate_ca_key",
					DNSNames:         []string{"test.smallstep.com"},
					Password:         "pass",
					AuthorityConfig:  ac,
					TLS: &TLSOptions{
						CipherSuites: CipherSuites{
							"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
						},
						MinVersion:    1.2,
						MaxVersion:    1.1,
						Renegotiation: true,
					},
				},
				err: errors.New("tls minVersion cannot exceed tls maxVersion"),
			}
		},
	}

	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			err := tc.config.Validate()
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					fmt.Printf("tc.tls = %v\n", tc.tls)
					fmt.Printf("*tc.config.TLS = %v\n", tc.config.TLS)
					assert.Equals(t, tc.config.TLS, tc.tls)
				}
			}
		})
	}
}

func TestAuthConfigValidate(t *testing.T) {
	asn1dn := ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "test",
	}

	maxjwk, err := jose.ReadKey("../testdata/secrets/max_pub.jwk")
	assert.FatalError(t, err)
	clijwk, err := jose.ReadKey("../testdata/secrets/step_cli_key_pub.jwk")
	assert.FatalError(t, err)
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
		},
	}

	type AuthConfigValidateTest struct {
		ac     *AuthConfig
		asn1dn ASN1DN
		err    error
	}
	tests := map[string]func(*testing.T) AuthConfigValidateTest{
		"fail-nil-authconfig": func(t *testing.T) AuthConfigValidateTest {
			return AuthConfigValidateTest{
				ac:  nil,
				err: errors.New("authority cannot be undefined"),
			}
		},
		"ok-empty-provisioners": func(t *testing.T) AuthConfigValidateTest {
			return AuthConfigValidateTest{
				ac:     &AuthConfig{},
				asn1dn: ASN1DN{},
			}
		},
		"ok-empty-asn1dn-template": func(t *testing.T) AuthConfigValidateTest {
			return AuthConfigValidateTest{
				ac: &AuthConfig{
					Provisioners: p,
				},
				asn1dn: ASN1DN{},
			}
		},
		"ok-custom-asn1dn": func(t *testing.T) AuthConfigValidateTest {
			return AuthConfigValidateTest{
				ac: &AuthConfig{
					Provisioners: p,
					Template:     &asn1dn,
				},
				asn1dn: asn1dn,
			}
		},
	}

	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			err := tc.ac.Validate(provisioner.Audiences{})
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				if assert.Nil(t, tc.err, fmt.Sprintf("expected error: %s, but got <nil>", tc.err)) {
					assert.Equals(t, *tc.ac.Template, tc.asn1dn)
				}
			}
		})
	}
}

func Test_toHostname(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "localhost", want: "localhost"},
		{name: "ca.smallstep.com", want: "ca.smallstep.com"},
		{name: "127.0.0.1", want: "127.0.0.1"},
		{name: "::1", want: "[::1]"},
		{name: "[::1]", want: "[::1]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toHostname(tt.name); got != tt.want {
				t.Errorf("toHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Audience(t *testing.T) {
	type fields struct {
		DNSNames []string
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []string
	}{
		{"ok", fields{[]string{
			"ca", "ca.example.com", "127.0.0.1", "::1",
		}}, args{"/path"}, []string{
			"https://ca/path",
			"https://ca.example.com/path",
			"https://127.0.0.1/path",
			"https://[::1]/path",
			"/path",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				DNSNames: tt.fields.DNSNames,
			}
			if got := c.Audience(tt.args.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Config.Audience() = %v, want %v", got, tt.want)
			}
		})
	}
}
