package authority

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"go.step.sm/linkedca"

	authPolicy "github.com/smallstep/certificates/authority/policy"
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
					err: errors.New("cannot parse permitted domain constraint \"**.local\": domain constraint \"**.local\" can only have wildcard as starting character"),
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
					err: errors.New("cannot parse domain: dns \"*\" cannot be converted to ASCII"),
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
					err: errors.New("the provided policy would lock out [step] from the CA. Please update your policy to include [step] as an allowed name"),
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
					err: errors.New("cannot parse domain: dns \"**\" cannot be converted to ASCII"),
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
					err: errors.New("the provided policy would lock out [otherAdmin] from the CA. Please update your policy to include [otherAdmin] as an allowed name"),
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

				pe, ok := err.(*PolicyError)
				assert.True(t, ok)

				assert.Equal(t, tc.err.Typ, pe.Typ)
				assert.Equal(t, tc.err.Error(), pe.Error())
			}
		})
	}
}

func Test_policyToCertificates(t *testing.T) {
	tests := []struct {
		name   string
		policy *linkedca.Policy
		want   *authPolicy.Options
	}{
		{
			name:   "no-policy",
			policy: nil,
			want:   nil,
		},
		{
			name: "full-policy",
			policy: &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns:    []string{"step"},
						Ips:    []string{"127.0.0.1/24"},
						Emails: []string{"*.example.com"},
						Uris:   []string{"https://*.local"},
					},
					Deny: &linkedca.X509Names{
						Dns:    []string{"bad"},
						Ips:    []string{"127.0.0.30"},
						Emails: []string{"badhost.example.com"},
						Uris:   []string{"https://badhost.local"},
					},
				},
				Ssh: &linkedca.SSHPolicy{
					Host: &linkedca.SSHHostPolicy{
						Allow: &linkedca.SSHHostNames{
							Dns:        []string{"*.localhost"},
							Ips:        []string{"127.0.0.1/24"},
							Principals: []string{"user"},
						},
						Deny: &linkedca.SSHHostNames{
							Dns:        []string{"badhost.localhost"},
							Ips:        []string{"127.0.0.40"},
							Principals: []string{"root"},
						},
					},
					User: &linkedca.SSHUserPolicy{
						Allow: &linkedca.SSHUserNames{
							Emails:     []string{"@work"},
							Principals: []string{"user"},
						},
						Deny: &linkedca.SSHUserNames{
							Emails:     []string{"root@work"},
							Principals: []string{"root"},
						},
					},
				},
			},
			want: &authPolicy.Options{
				X509: &authPolicy.X509PolicyOptions{
					AllowedNames: &authPolicy.X509NameOptions{
						DNSDomains:     []string{"step"},
						IPRanges:       []string{"127.0.0.1/24"},
						EmailAddresses: []string{"*.example.com"},
						URIDomains:     []string{"https://*.local"},
					},
					DeniedNames: &authPolicy.X509NameOptions{
						DNSDomains:     []string{"bad"},
						IPRanges:       []string{"127.0.0.30"},
						EmailAddresses: []string{"badhost.example.com"},
						URIDomains:     []string{"https://badhost.local"},
					},
				},
				SSH: &authPolicy.SSHPolicyOptions{
					Host: &authPolicy.SSHHostCertificateOptions{
						AllowedNames: &authPolicy.SSHNameOptions{
							DNSDomains: []string{"*.localhost"},
							IPRanges:   []string{"127.0.0.1/24"},
							Principals: []string{"user"},
						},
						DeniedNames: &authPolicy.SSHNameOptions{
							DNSDomains: []string{"badhost.localhost"},
							IPRanges:   []string{"127.0.0.40"},
							Principals: []string{"root"},
						},
					},
					User: &authPolicy.SSHUserCertificateOptions{
						AllowedNames: &authPolicy.SSHNameOptions{
							EmailAddresses: []string{"@work"},
							Principals:     []string{"user"},
						},
						DeniedNames: &authPolicy.SSHNameOptions{
							EmailAddresses: []string{"root@work"},
							Principals:     []string{"root"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyToCertificates(tt.policy)
			if !cmp.Equal(tt.want, got) {
				t.Errorf("policyToCertificates() diff=\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}
