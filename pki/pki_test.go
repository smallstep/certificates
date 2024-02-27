package pki

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/smallstep/certificates/authority/admin"
	admindb "github.com/smallstep/certificates/authority/admin/db/nosql"
	authconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/cli-utils/step"
)

func withDBDataSource(t *testing.T, dataSource string) func(c *authconfig.Config) error {
	return func(c *authconfig.Config) error {
		if c == nil || c.DB == nil {
			require.Fail(t, "withDBDataSource prerequisites not met")
		}
		c.DB.DataSource = dataSource
		return nil
	}
}

func TestPKI_GenerateConfig(t *testing.T) {
	var preparePKI = func(t *testing.T, opts ...Option) *PKI {
		o := apiv1.Options{
			Type:      "softcas",
			IsCreator: true,
		}

		// TODO(hs): invoking `New` doesn't perform all operations that are executed
		// when `ca init` is executed. Ideally this logic should be handled in one
		// place and probably inside of the PKI initialization. For testing purposes
		// the missing operations are faked by `setKeyPair`.
		p, err := New(o, opts...)
		require.NoError(t, err)

		// setKeyPair sets a predefined JWK and a default JWK provisioner. This is one
		// of the things performed in the `ca init` code that's not part of `New`, but
		// performed after that in p.GenerateKeyPairs`. We're currently using the same
		// JWK for every test to keep test variance small: we're not testing JWK generation
		// here after all. It's a bit dangerous to redefine the function here, but it's
		// the simplest way to make this fully testable without refactoring the init now.
		// The password for the predefined encrypted key is \x01\x03\x03\x07.
		setKeyPair(t, p)

		return p
	}
	type args struct {
		opt []ConfigOption
	}
	type test struct {
		pki     *PKI
		args    args
		want    *authconfig.Config
		wantErr bool
	}
	var tests = map[string]func(t *testing.T) test{
		"ok/simple": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "default-prov"
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    false,
						Provisioners: provisioner.List{
							&provisioner.JWK{
								Type: "JWK",
								Name: "default-prov",
							},
						},
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(step.Path(), "db"),
					},
				},
				wantErr: false,
			}
		},
		"ok/with-acme": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "default-prov"
			pki.options.enableACME = true
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    false,
						Provisioners: provisioner.List{
							&provisioner.JWK{
								Type: "JWK",
								Name: "default-prov",
							},
							&provisioner.ACME{
								Type: "ACME",
								Name: "acme",
							},
						},
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(step.Path(), "db"),
					},
				},
				wantErr: false,
			}
		},
		"ok/with-acme-and-double-provisioner-name": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "acme"
			pki.options.enableACME = true
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    false,
						Provisioners: provisioner.List{
							&provisioner.JWK{
								Type: "JWK",
								Name: "acme",
							},
							&provisioner.ACME{
								Type: "ACME",
								Name: "acme-1",
							},
						},
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(step.Path(), "db"),
					},
				},
				wantErr: false,
			}
		},
		"ok/with-ssh": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "default-prov"
			pki.options.enableSSH = true
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    false,
						Provisioners: provisioner.List{
							&provisioner.JWK{
								Type: "JWK",
								Name: "default-prov",
							},
							&provisioner.SSHPOP{
								Type: "SSHPOP",
								Name: "sshpop",
							},
						},
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(step.Path(), "db"),
					},
				},
				wantErr: false,
			}
		},
		"ok/with-ssh-and-double-provisioner-name": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "sshpop"
			pki.options.enableSSH = true
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    false,
						Provisioners: provisioner.List{
							&provisioner.JWK{
								Type: "JWK",
								Name: "sshpop",
							},
							&provisioner.SSHPOP{
								Type: "SSHPOP",
								Name: "sshpop-1",
							},
						},
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(step.Path(), "db"),
					},
				},
				wantErr: false,
			}
		},
		"ok/with-admin": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.options.deploymentType = StandaloneDeployment
			pki.options.provisioner = "default-prov"
			pki.options.enableAdmin = true
			tempDir := t.TempDir()
			return test{
				pki: pki,
				args: args{
					[]ConfigOption{withDBDataSource(t, filepath.Join(tempDir, "db"))},
				},
				want: &authconfig.Config{
					Address:         "127.0.0.1:9000",
					InsecureAddress: "",
					DNSNames:        []string{"127.0.0.1"},
					AuthorityConfig: &authconfig.AuthConfig{
						DeploymentType: "", // TODO(hs): (why is) this is not set to standalone?
						EnableAdmin:    true,
						Provisioners:   provisioner.List{}, // when admin is enabled, provisioner list is expected to be empty
					},
					DB: &db.Config{
						Type:       "badgerv2",
						DataSource: filepath.Join(tempDir, "db"),
					},
				},
				wantErr: false,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			got, err := tc.pki.GenerateConfig(tc.args.opt...)
			if tc.wantErr {
				assert.NotNil(t, err)
				assert.Nil(t, got)
				return
			}

			assert.Nil(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, tc.want.Address, got.Address)
				assert.Equal(t, tc.want.InsecureAddress, got.InsecureAddress)
				assert.Equal(t, tc.want.DNSNames, got.DNSNames)
				assert.Equal(t, tc.want.DB, got.DB)
				if assert.NotNil(t, tc.want.AuthorityConfig) {
					assert.Equal(t, tc.want.AuthorityConfig.DeploymentType, got.AuthorityConfig.DeploymentType)
					assert.Equal(t, tc.want.AuthorityConfig.EnableAdmin, got.AuthorityConfig.EnableAdmin)
					if numberOfProvisioners := len(tc.want.AuthorityConfig.Provisioners); numberOfProvisioners > 0 {
						if assert.Len(t, got.AuthorityConfig.Provisioners, numberOfProvisioners) {
							for i, p := range tc.want.AuthorityConfig.Provisioners {
								assert.Equal(t, p.GetType(), got.AuthorityConfig.Provisioners[i].GetType())
								assert.Equal(t, p.GetName(), got.AuthorityConfig.Provisioners[i].GetName())
							}
						}
					}
					if tc.want.AuthorityConfig.EnableAdmin {
						_db, err := db.New(tc.want.DB)
						require.NoError(t, err)
						defer _db.Shutdown()

						adminDB, err := admindb.New(_db.(nosql.DB), admin.DefaultAuthorityID)
						require.NoError(t, err)

						provs, err := adminDB.GetProvisioners(context.Background())
						require.NoError(t, err)

						assert.NotEmpty(t, provs) // currently about the best we can do in terms of checks
					}
				}
			}
		})
	}
}
