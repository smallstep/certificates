package policy

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"go.step.sm/linkedca"
)

func TestPolicyToCertificates(t *testing.T) {
	type args struct {
		policy *linkedca.Policy
	}
	tests := []struct {
		name string
		args args
		want *Options
	}{
		{
			name: "nil",
			args: args{
				policy: nil,
			},
			want: nil,
		},
		{
			name: "no-policy",
			args: args{
				&linkedca.Policy{},
			},
			want: nil,
		},
		{
			name: "partial-policy",
			args: args{
				&linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
						AllowWildcardNames: false,
					},
				},
			},
			want: &Options{
				X509: &X509PolicyOptions{
					AllowedNames: &X509NameOptions{
						DNSDomains: []string{"*.local"},
					},
					AllowWildcardNames: false,
				},
			},
		},
		{
			name: "full-policy",
			args: args{
				&linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns:         []string{"step"},
							Ips:         []string{"127.0.0.1/24"},
							Emails:      []string{"*.example.com"},
							Uris:        []string{"https://*.local"},
							CommonNames: []string{"some name"},
						},
						Deny: &linkedca.X509Names{
							Dns:         []string{"bad"},
							Ips:         []string{"127.0.0.30"},
							Emails:      []string{"badhost.example.com"},
							Uris:        []string{"https://badhost.local"},
							CommonNames: []string{"another name"},
						},
						AllowWildcardNames: true,
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
			},
			want: &Options{
				X509: &X509PolicyOptions{
					AllowedNames: &X509NameOptions{
						DNSDomains:     []string{"step"},
						IPRanges:       []string{"127.0.0.1/24"},
						EmailAddresses: []string{"*.example.com"},
						URIDomains:     []string{"https://*.local"},
						CommonNames:    []string{"some name"},
					},
					DeniedNames: &X509NameOptions{
						DNSDomains:     []string{"bad"},
						IPRanges:       []string{"127.0.0.30"},
						EmailAddresses: []string{"badhost.example.com"},
						URIDomains:     []string{"https://badhost.local"},
						CommonNames:    []string{"another name"},
					},
					AllowWildcardNames: true,
				},
				SSH: &SSHPolicyOptions{
					Host: &SSHHostCertificateOptions{
						AllowedNames: &SSHNameOptions{
							DNSDomains: []string{"*.localhost"},
							IPRanges:   []string{"127.0.0.1/24"},
							Principals: []string{"user"},
						},
						DeniedNames: &SSHNameOptions{
							DNSDomains: []string{"badhost.localhost"},
							IPRanges:   []string{"127.0.0.40"},
							Principals: []string{"root"},
						},
					},
					User: &SSHUserCertificateOptions{
						AllowedNames: &SSHNameOptions{
							EmailAddresses: []string{"@work"},
							Principals:     []string{"user"},
						},
						DeniedNames: &SSHNameOptions{
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
			got := LinkedToCertificates(tt.args.policy)
			if !cmp.Equal(tt.want, got) {
				t.Errorf("policyToCertificates() diff=\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}
