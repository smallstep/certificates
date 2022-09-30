package authority

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/administrator"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

func TestAuthority_checkPolicy(t *testing.T) {
	type test struct {
		ctx          context.Context
		currentAdmin *linkedca.Admin
		otherAdmins  []*linkedca.Admin
		policy       *linkedca.Policy
		err          *PolicyError
	}
	tests := map[string]func(t *testing.T) test{
		"fail/NewX509PolicyEngine-error": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"**.local"},
						},
					},
				},
				err: &PolicyError{
					Typ: ConfigurationFailure,
					Err: errors.New("cannot parse permitted domain constraint \"**.local\": domain constraint \"**.local\" can only have wildcard as starting character"),
				},
			}
		},
		"fail/currentAdmin-evaluation-error": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "*"},
				otherAdmins:  []*linkedca.Admin{},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				},
				err: &PolicyError{
					Typ: EvaluationFailure,
					Err: errors.New("cannot parse dns domain \"*\""),
				},
			}
		},
		"fail/currentAdmin-lockout": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins: []*linkedca.Admin{
					{
						Subject: "otherAdmin",
					},
				},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				},
				err: &PolicyError{
					Typ: AdminLockOut,
					Err: errors.New("the provided policy would lock out [step] from the CA. Please update your policy to include [step] as an allowed name"),
				},
			}
		},
		"fail/otherAdmins-evaluation-error": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins: []*linkedca.Admin{
					{
						Subject: "other",
					},
					{
						Subject: "**",
					},
				},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "other", "*.local"},
						},
					},
				},
				err: &PolicyError{
					Typ: EvaluationFailure,
					Err: errors.New("cannot parse dns domain \"**\""),
				},
			}
		},
		"fail/otherAdmins-lockout": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins: []*linkedca.Admin{
					{
						Subject: "otherAdmin",
					},
				},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step"},
						},
					},
				},
				err: &PolicyError{
					Typ: AdminLockOut,
					Err: errors.New("the provided policy would lock out [otherAdmin] from the CA. Please update your policy to include [otherAdmin] as an allowed name"),
				},
			}
		},
		"ok/no-policy": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins:  []*linkedca.Admin{},
				policy:       nil,
			}
		},
		"ok/empty-policy": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins:  []*linkedca.Admin{},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{},
						},
					},
				},
			}
		},
		"ok/policy": func(t *testing.T) test {
			return test{
				ctx:          context.Background(),
				currentAdmin: &linkedca.Admin{Subject: "step"},
				otherAdmins: []*linkedca.Admin{
					{
						Subject: "otherAdmin",
					},
				},
				policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			}
		},
	}

	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			a := &Authority{}

			err := a.checkPolicy(tc.ctx, tc.currentAdmin, tc.otherAdmins, tc.policy)

			if tc.err == nil {
				assert.Nil(t, err)
			} else {
				assert.IsType(t, &PolicyError{}, err)

				var pe *PolicyError
				if assert.True(t, errors.As(err, &pe)) {
					assert.Equal(t, tc.err.Typ, pe.Typ)
					assert.Equal(t, tc.err.Error(), pe.Error())
				}
			}
		})
	}
}

func mustPolicyEngine(t *testing.T, options *policy.Options) *policy.Engine {
	engine, err := policy.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestAuthority_reloadPolicyEngines(t *testing.T) {

	existingPolicyEngine, err := policy.New(&policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.hosts.example.com"},
			},
		},
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.hosts.example.com"},
				},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					EmailAddresses: []string{"@mails.example.com"},
				},
			},
		},
	})
	assert.NoError(t, err)

	newX509Options := &policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.local"},
			},
			DeniedNames: &policy.X509NameOptions{
				DNSDomains: []string{"badhost.local"},
			},
			AllowWildcardNames: true,
		},
	}

	newSSHHostOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
				DeniedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"badhost.local"},
				},
			},
		},
	}

	newSSHUserOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					Principals: []string{"*"},
				},
				DeniedNames: &policy.SSHNameOptions{
					Principals: []string{"root"},
				},
			},
		},
	}

	newSSHOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
				DeniedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"badhost.local"},
				},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					Principals: []string{"*"},
				},
				DeniedNames: &policy.SSHNameOptions{
					Principals: []string{"root"},
				},
			},
		},
	}

	newOptions := &policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.local"},
			},
			DeniedNames: &policy.X509NameOptions{
				DNSDomains: []string{"badhost.local"},
			},
			AllowWildcardNames: true,
		},
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
				DeniedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"badhost.local"},
				},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					Principals: []string{"*"},
				},
				DeniedNames: &policy.SSHNameOptions{
					Principals: []string{"root"},
				},
			},
		},
	}

	newAdminX509Options := &policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.local"},
			},
		},
	}

	newAdminSSHHostOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
			},
		},
	}

	newAdminSSHUserOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					EmailAddresses: []string{"@example.com"},
				},
			},
		},
	}

	newAdminOptions := &policy.Options{
		X509: &policy.X509PolicyOptions{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.local"},
			},
			DeniedNames: &policy.X509NameOptions{
				DNSDomains: []string{"badhost.local"},
			},
			AllowWildcardNames: true,
		},
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
				DeniedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"badhost.local"},
				},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					EmailAddresses: []string{"@example.com"},
				},
				DeniedNames: &policy.SSHNameOptions{
					EmailAddresses: []string{"baduser@example.com"},
				},
			},
		},
	}

	tests := []struct {
		name     string
		config   *config.Config
		adminDB  admin.DB
		ctx      context.Context
		expected *policy.Engine
		wantErr  bool
	}{
		{
			name: "fail/standalone-x509-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						X509: &policy.X509PolicyOptions{
							AllowedNames: &policy.X509NameOptions{
								DNSDomains: []string{"**.local"},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/standalone-ssh-host-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							Host: &policy.SSHHostCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"**.local"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/standalone-ssh-user-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							User: &policy.SSHUserCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									EmailAddresses: []string{"**example.com"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/adminDB.GetAuthorityPolicy-error",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return nil, errors.New("force")
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/admin-x509-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						X509: &linkedca.X509Policy{
							Allow: &linkedca.X509Names{
								Dns: []string{"**.local"},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/admin-ssh-host-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						Ssh: &linkedca.SSHPolicy{
							Host: &linkedca.SSHHostPolicy{
								Allow: &linkedca.SSHHostNames{
									Dns: []string{"**.local"},
								},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "fail/admin-ssh-user-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						Ssh: &linkedca.SSHPolicy{
							User: &linkedca.SSHUserPolicy{
								Allow: &linkedca.SSHUserNames{
									Emails: []string{"@@example.com"},
								},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  true,
			expected: existingPolicyEngine,
		},
		{
			name: "ok/linkedca-unsupported",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB:  &linkedCaClient{},
			ctx:      context.Background(),
			wantErr:  false,
			expected: existingPolicyEngine,
		},
		{
			name: "ok/standalone-no-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy:      nil,
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, nil),
		},
		{
			name: "ok/standalone-x509-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						X509: &policy.X509PolicyOptions{
							AllowedNames: &policy.X509NameOptions{
								DNSDomains: []string{"*.local"},
							},
							DeniedNames: &policy.X509NameOptions{
								DNSDomains: []string{"badhost.local"},
							},
							AllowWildcardNames: true,
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newX509Options),
		},
		{
			name: "ok/standalone-ssh-host-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							Host: &policy.SSHHostCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"*.local"},
								},
								DeniedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"badhost.local"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newSSHHostOptions),
		},
		{
			name: "ok/standalone-ssh-user-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							User: &policy.SSHUserCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									Principals: []string{"*"},
								},
								DeniedNames: &policy.SSHNameOptions{
									Principals: []string{"root"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newSSHUserOptions),
		},
		{
			name: "ok/standalone-ssh-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							Host: &policy.SSHHostCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"*.local"},
								},
								DeniedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"badhost.local"},
								},
							},
							User: &policy.SSHUserCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									Principals: []string{"*"},
								},
								DeniedNames: &policy.SSHNameOptions{
									Principals: []string{"root"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newSSHOptions),
		},
		{
			name: "ok/standalone-full-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: false,
					Policy: &policy.Options{
						X509: &policy.X509PolicyOptions{
							AllowedNames: &policy.X509NameOptions{
								DNSDomains: []string{"*.local"},
							},
							DeniedNames: &policy.X509NameOptions{
								DNSDomains: []string{"badhost.local"},
							},
							AllowWildcardNames: true,
						},
						SSH: &policy.SSHPolicyOptions{
							Host: &policy.SSHHostCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"*.local"},
								},
								DeniedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"badhost.local"},
								},
							},
							User: &policy.SSHUserCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									Principals: []string{"*"},
								},
								DeniedNames: &policy.SSHNameOptions{
									Principals: []string{"root"},
								},
							},
						},
					},
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newOptions),
		},
		{
			name: "ok/admin-x509-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						X509: &linkedca.X509Policy{
							Allow: &linkedca.X509Names{
								Dns: []string{"*.local"},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newAdminX509Options),
		},
		{
			name: "ok/admin-ssh-host-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						Ssh: &linkedca.SSHPolicy{
							Host: &linkedca.SSHHostPolicy{
								Allow: &linkedca.SSHHostNames{
									Dns: []string{"*.local"},
								},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newAdminSSHHostOptions),
		},
		{
			name: "ok/admin-ssh-user-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						Ssh: &linkedca.SSHPolicy{
							User: &linkedca.SSHUserPolicy{
								Allow: &linkedca.SSHUserNames{
									Emails: []string{"@example.com"},
								},
							},
						},
					}, nil
				},
			},
			ctx:      context.Background(),
			wantErr:  false,
			expected: mustPolicyEngine(t, newAdminSSHUserOptions),
		},
		{
			name: "ok/admin-full-policy",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
				},
			},
			ctx: context.Background(),
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						X509: &linkedca.X509Policy{
							Allow: &linkedca.X509Names{
								Dns: []string{"*.local"},
							},
							Deny: &linkedca.X509Names{
								Dns: []string{"badhost.local"},
							},
							AllowWildcardNames: true,
						},
						Ssh: &linkedca.SSHPolicy{
							Host: &linkedca.SSHHostPolicy{
								Allow: &linkedca.SSHHostNames{
									Dns: []string{"*.local"},
								},
								Deny: &linkedca.SSHHostNames{
									Dns: []string{"badhost.local"},
								},
							},
							User: &linkedca.SSHUserPolicy{
								Allow: &linkedca.SSHUserNames{
									Emails: []string{"@example.com"},
								},
								Deny: &linkedca.SSHUserNames{
									Emails: []string{"baduser@example.com"},
								},
							},
						},
					}, nil
				},
			},
			wantErr:  false,
			expected: mustPolicyEngine(t, newAdminOptions),
		},
		{
			// both DB and JSON config; DB config is taken if Admin API is enabled
			name: "ok/admin-over-standalone",
			config: &config.Config{
				AuthorityConfig: &config.AuthConfig{
					EnableAdmin: true,
					Policy: &policy.Options{
						SSH: &policy.SSHPolicyOptions{
							Host: &policy.SSHHostCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"*.local"},
								},
								DeniedNames: &policy.SSHNameOptions{
									DNSDomains: []string{"badhost.local"},
								},
							},
							User: &policy.SSHUserCertificateOptions{
								AllowedNames: &policy.SSHNameOptions{
									Principals: []string{"*"},
								},
								DeniedNames: &policy.SSHNameOptions{
									Principals: []string{"root"},
								},
							},
						},
					},
				},
			},
			ctx: context.Background(),
			adminDB: &admin.MockDB{
				MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
					return &linkedca.Policy{
						X509: &linkedca.X509Policy{
							Allow: &linkedca.X509Names{
								Dns: []string{"*.local"},
							},
							Deny: &linkedca.X509Names{
								Dns: []string{"badhost.local"},
							},
							AllowWildcardNames: true,
						},
					}, nil
				},
			},
			wantErr:  false,
			expected: mustPolicyEngine(t, newX509Options),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:       tt.config,
				adminDB:      tt.adminDB,
				policyEngine: existingPolicyEngine,
			}
			if err := a.reloadPolicyEngines(tt.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Authority.reloadPolicyEngines() error = %v, wantErr %v", err, tt.wantErr)
			}

			assert.Equal(t, tt.expected, a.policyEngine)
		})
	}
}

func TestAuthority_checkAuthorityPolicy(t *testing.T) {
	type fields struct {
		provisioners *provisioner.Collection
		admins       *administrator.Collection
		db           db.AuthDB
		adminDB      admin.DB
	}
	type args struct {
		ctx          context.Context
		currentAdmin *linkedca.Admin
		provName     string
		p            *linkedca.Policy
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "no policy",
			fields: fields{},
			args: args{
				currentAdmin: nil,
				provName:     "prov",
				p:            nil,
			},
			wantErr: false,
		},
		{
			name: "fail/adminDB.GetAdmins-error",
			fields: fields{
				admins: administrator.NewCollection(nil),
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return nil, errors.New("force")
					},
				},
			},
			args: args{
				currentAdmin: &linkedca.Admin{Subject: "step"},
				provName:     "prov",
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fail/policy",
			fields: fields{
				admins: administrator.NewCollection(nil),
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							{
								Id:      "adminID1",
								Subject: "anotherAdmin",
							},
							{
								Id:      "adminID2",
								Subject: "step",
							},
							{
								Id:      "adminID3",
								Subject: "otherAdmin",
							},
						}, nil
					},
				},
			},
			args: args{
				currentAdmin: &linkedca.Admin{Subject: "step"},
				provName:     "prov",
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ok",
			fields: fields{
				admins: administrator.NewCollection(nil),
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							{
								Id:      "adminID2",
								Subject: "step",
							},
							{
								Id:      "adminID3",
								Subject: "otherAdmin",
							},
						}, nil
					},
				},
			},
			args: args{
				currentAdmin: &linkedca.Admin{Subject: "step"},
				provName:     "prov",
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				provisioners: tt.fields.provisioners,
				admins:       tt.fields.admins,
				db:           tt.fields.db,
				adminDB:      tt.fields.adminDB,
			}
			if err := a.checkAuthorityPolicy(tt.args.ctx, tt.args.currentAdmin, tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("Authority.checkProvisionerPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthority_checkProvisionerPolicy(t *testing.T) {
	jwkProvisioner := &provisioner.JWK{
		ID:   "jwkID",
		Type: "JWK",
		Name: "jwkProv",
		Key:  &jose.JSONWebKey{KeyID: "jwkKeyID"},
	}
	provisioners := provisioner.NewCollection(testAudiences)
	provisioners.Store(jwkProvisioner)
	admins := administrator.NewCollection(provisioners)
	admins.Store(&linkedca.Admin{
		Id:            "adminID",
		Subject:       "step",
		ProvisionerId: "jwkID",
	}, jwkProvisioner)
	type fields struct {
		provisioners *provisioner.Collection
		admins       *administrator.Collection
		db           db.AuthDB
		adminDB      admin.DB
	}
	type args struct {
		ctx      context.Context
		provName string
		p        *linkedca.Policy
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "no policy",
			fields: fields{},
			args: args{
				provName: "prov",
				p:        nil,
			},
			wantErr: false,
		},
		{
			name: "fail/policy",
			fields: fields{
				provisioners: provisioners,
				admins:       admins,
			},
			args: args{
				provName: "jwkProv",
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"otherAdmin"}, // step not in policy
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ok",
			fields: fields{
				provisioners: provisioners,
				admins:       admins,
			},
			args: args{
				provName: "jwkProv",
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				provisioners: tt.fields.provisioners,
				admins:       tt.fields.admins,
				db:           tt.fields.db,
				adminDB:      tt.fields.adminDB,
			}
			if err := a.checkProvisionerPolicy(tt.args.ctx, tt.args.provName, tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("Authority.checkProvisionerPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthority_RemoveAuthorityPolicy(t *testing.T) {
	type fields struct {
		config  *config.Config
		db      db.AuthDB
		adminDB admin.DB
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr *PolicyError
	}{
		{
			name: "fail/adminDB.DeleteAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockDeleteAuthorityPolicy: func(ctx context.Context) error {
						return errors.New("force")
					},
				},
			},
			wantErr: &PolicyError{
				Typ: StoreFailure,
				Err: errors.New("force"),
			},
		},
		{
			name: "fail/a.reloadPolicyEngines",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockDeleteAuthorityPolicy: func(ctx context.Context) error {
						return nil
					},
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, errors.New("force")
					},
				},
			},
			wantErr: &PolicyError{
				Typ: ReloadFailure,
				Err: errors.New("error reloading policy engines when deleting authority policy: error getting policy to (re)load policy engines: force"),
			},
		},
		{
			name: "ok",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockDeleteAuthorityPolicy: func(ctx context.Context) error {
						return nil
					},
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, nil
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:  tt.fields.config,
				db:      tt.fields.db,
				adminDB: tt.fields.adminDB,
			}
			err := a.RemoveAuthorityPolicy(tt.args.ctx)
			if err != nil {
				var pe *PolicyError
				if assert.True(t, errors.As(err, &pe)) {
					assert.Equal(t, tt.wantErr.Typ, pe.Typ)
					assert.Equal(t, tt.wantErr.Err.Error(), pe.Err.Error())
				}
				return
			}
		})
	}
}

func TestAuthority_GetAuthorityPolicy(t *testing.T) {
	type fields struct {
		config  *config.Config
		db      db.AuthDB
		adminDB admin.DB
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *linkedca.Policy
		wantErr *PolicyError
	}{
		{
			name: "fail/adminDB.GetAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, errors.New("force")
					},
				},
			},
			wantErr: &PolicyError{
				Typ: InternalFailure,
				Err: errors.New("force"),
			},
		},
		{
			name: "ok",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return &linkedca.Policy{}, nil
					},
				},
			},
			want: &linkedca.Policy{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:  tt.fields.config,
				db:      tt.fields.db,
				adminDB: tt.fields.adminDB,
			}
			got, err := a.GetAuthorityPolicy(tt.args.ctx)
			if err != nil {
				var pe *PolicyError
				if assert.True(t, errors.As(err, &pe)) {
					assert.Equal(t, tt.wantErr.Typ, pe.Typ)
					assert.Equal(t, tt.wantErr.Err.Error(), pe.Err.Error())
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetAuthorityPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_CreateAuthorityPolicy(t *testing.T) {
	type fields struct {
		config  *config.Config
		db      db.AuthDB
		adminDB admin.DB
	}
	type args struct {
		ctx context.Context
		adm *linkedca.Admin
		p   *linkedca.Policy
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *linkedca.Policy
		wantErr *PolicyError
	}{
		{
			name: "fail/a.checkAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return nil, errors.New("force")
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: InternalFailure,
				Err: errors.New("error retrieving admins: force"),
			},
		},
		{
			name: "fail/adminDB.CreateAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
					MockCreateAuthorityPolicy: func(ctx context.Context, policy *linkedca.Policy) error {
						return errors.New("force")
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: StoreFailure,
				Err: errors.New("force"),
			},
		},
		{
			name: "fail/a.reloadPolicyEngines",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, errors.New("force")
					},
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: ReloadFailure,
				Err: errors.New("error reloading policy engines when creating authority policy: error getting policy to (re)load policy engines: force"),
			},
		},
		{
			name: "ok",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return &linkedca.Policy{
							X509: &linkedca.X509Policy{
								Allow: &linkedca.X509Names{
									Dns: []string{"step", "otherAdmin"},
								},
							},
						}, nil
					},
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			want: &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"step", "otherAdmin"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:  tt.fields.config,
				db:      tt.fields.db,
				adminDB: tt.fields.adminDB,
			}
			got, err := a.CreateAuthorityPolicy(tt.args.ctx, tt.args.adm, tt.args.p)
			if err != nil {
				var pe *PolicyError
				if assert.True(t, errors.As(err, &pe)) {
					assert.Equal(t, tt.wantErr.Typ, pe.Typ)
					assert.Equal(t, tt.wantErr.Err.Error(), pe.Err.Error())
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.CreateAuthorityPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_UpdateAuthorityPolicy(t *testing.T) {
	type fields struct {
		config  *config.Config
		db      db.AuthDB
		adminDB admin.DB
	}
	type args struct {
		ctx context.Context
		adm *linkedca.Admin
		p   *linkedca.Policy
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *linkedca.Policy
		wantErr *PolicyError
	}{
		{
			name: "fail/a.checkAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return nil, errors.New("force")
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: InternalFailure,
				Err: errors.New("error retrieving admins: force"),
			},
		},
		{
			name: "fail/adminDB.UpdateAuthorityPolicy",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
					MockUpdateAuthorityPolicy: func(ctx context.Context, policy *linkedca.Policy) error {
						return errors.New("force")
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: StoreFailure,
				Err: errors.New("force"),
			},
		},
		{
			name: "fail/a.reloadPolicyEngines",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, errors.New("force")
					},
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			wantErr: &PolicyError{
				Typ: ReloadFailure,
				Err: errors.New("error reloading policy engines when updating authority policy: error getting policy to (re)load policy engines: force"),
			},
		},
		{
			name: "ok",
			fields: fields{
				config: &config.Config{
					AuthorityConfig: &config.AuthConfig{
						EnableAdmin: true,
					},
				},
				adminDB: &admin.MockDB{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return &linkedca.Policy{
							X509: &linkedca.X509Policy{
								Allow: &linkedca.X509Names{
									Dns: []string{"step", "otherAdmin"},
								},
							},
						}, nil
					},
					MockUpdateAuthorityPolicy: func(ctx context.Context, policy *linkedca.Policy) error {
						return nil
					},
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{}, nil
					},
				},
			},
			args: args{
				ctx: context.Background(),
				adm: &linkedca.Admin{Subject: "step"},
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"step", "otherAdmin"},
						},
					},
				},
			},
			want: &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"step", "otherAdmin"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:  tt.fields.config,
				db:      tt.fields.db,
				adminDB: tt.fields.adminDB,
			}
			got, err := a.UpdateAuthorityPolicy(tt.args.ctx, tt.args.adm, tt.args.p)
			if err != nil {
				var pe *PolicyError
				if assert.True(t, errors.As(err, &pe)) {
					assert.Equal(t, tt.wantErr.Typ, pe.Typ)
					assert.Equal(t, tt.wantErr.Err.Error(), pe.Err.Error())
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.UpdateAuthorityPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}
