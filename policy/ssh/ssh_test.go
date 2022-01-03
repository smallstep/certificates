package sshpolicy

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNamePolicyEngine_ArePrincipalsAllowed(t *testing.T) {
	type fields struct {
		options                 []NamePolicyOption
		permittedDNSDomains     []string
		excludedDNSDomains      []string
		permittedEmailAddresses []string
		excludedEmailAddresses  []string
		permittedPrincipals     []string
		excludedPrincipals      []string
	}
	tests := []struct {
		name    string
		fields  fields
		cert    *ssh.Certificate
		want    bool
		wantErr bool
	}{
		{
			name: "fail/dns-permitted",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"host.notlocal"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted",
			fields: fields{
				excludedDNSDomains: []string{".local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"host.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user@example.notlocal"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-excluded",
			fields: fields{
				excludedEmailAddresses: []string{"example.local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user@example.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/principal-permitted",
			fields: fields{
				permittedPrincipals: []string{"user1"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user2"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/principal-excluded",
			fields: fields{
				excludedPrincipals: []string{"user"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/combined-complex-all-badhost.local",
			fields: fields{
				permittedDNSDomains:     []string{".local"},
				permittedEmailAddresses: []string{"example.local"},
				permittedPrincipals:     []string{"user"},
				excludedDNSDomains:      []string{"badhost.local"},
				excludedEmailAddresses:  []string{"badmail@example.local"},
				excludedPrincipals:      []string{"baduser"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{
					"user",
					"user@example.local",
					"badhost.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name:   "ok/no-constraints",
			fields: fields{},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"host.example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-permitted",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-excluded",
			fields: fields{
				excludedDNSDomains: []string{".notlocal"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded",
			fields: fields{
				excludedEmailAddresses: []string{"example.notlocal"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/principal-permitted",
			fields: fields{
				permittedPrincipals: []string{"user"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/principal-excluded",
			fields: fields{
				excludedPrincipals: []string{"someone"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{"user"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-simple-user-permitted",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
				permittedPrincipals:     []string{"user"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{
					"user",
					"user@example.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-simple-all-permitted",
			fields: fields{
				permittedDNSDomains:     []string{".local"},
				permittedEmailAddresses: []string{"example.local"},
				permittedPrincipals:     []string{"user"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{
					"user",
					"user@example.local",
					"host.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-complex-all",
			fields: fields{
				permittedDNSDomains:     []string{".local"},
				permittedEmailAddresses: []string{"example.local"},
				permittedPrincipals:     []string{"user"},
				excludedDNSDomains:      []string{"badhost.local"},
				excludedEmailAddresses:  []string{"badmail@example.local"},
				excludedPrincipals:      []string{"baduser"},
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{
					"user",
					"user@example.local",
					"host.local",
				},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &NamePolicyEngine{
				options:                 tt.fields.options,
				permittedDNSDomains:     tt.fields.permittedDNSDomains,
				excludedDNSDomains:      tt.fields.excludedDNSDomains,
				permittedEmailAddresses: tt.fields.permittedEmailAddresses,
				excludedEmailAddresses:  tt.fields.excludedEmailAddresses,
				permittedPrincipals:     tt.fields.permittedPrincipals,
				excludedPrincipals:      tt.fields.excludedPrincipals,
			}
			got, err := e.ArePrincipalsAllowed(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.ArePrincipalsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.ArePrincipalsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
