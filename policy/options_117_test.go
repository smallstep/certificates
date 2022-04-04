//go:build !go1.18
// +build !go1.18

package policy

import "testing"

func Test_normalizeAndValidateURIDomainConstraint(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
		wantErr    bool
	}{
		{
			name:       "fail/empty-constraint",
			constraint: "",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/scheme-https",
			constraint: `https://*.local`,
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/too-many-asterisks",
			constraint: "**.local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/empty-label",
			constraint: "..local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/empty-reverse",
			constraint: ".",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/no-asterisk",
			constraint: ".example.com",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/domain-with-port",
			constraint: "host.local:8443",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/ipv4",
			constraint: "127.0.0.1",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/ipv6-brackets",
			constraint: "[::1]",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/ipv6-no-brackets",
			constraint: "::1",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/ipv6-no-brackets",
			constraint: "[::1",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/idna-internationalized-domain-name-lookup",
			constraint: `\00local`,
			want:       "",
			wantErr:    true,
		},
		{
			name:       "ok/wildcard",
			constraint: "*.local",
			want:       ".local",
			wantErr:    false,
		},
		{
			name:       "ok/specific-domain",
			constraint: "example.local",
			want:       "example.local",
			wantErr:    false,
		},
		{
			name:       "ok/idna-internationalized-domain-name-lookup",
			constraint: `*.bücher.example.com`,
			want:       ".xn--bcher-kva.example.com",
			wantErr:    false,
		},
		{
			// IDNA2003 vs. 2008 deviation: https://unicode.org/reports/tr46/#Deviations results
			// in a difference between Go 1.18 and lower versions. Go 1.18 expects ".xn--fa-hia.de"; not .fass.de.
			name:       "ok/idna-internationalized-domain-name-lookup-deviation",
			constraint: `*.faß.de`,
			want:       ".fass.de",
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAndValidateURIDomainConstraint(tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeAndValidateURIDomainConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("normalizeAndValidateURIDomainConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}
