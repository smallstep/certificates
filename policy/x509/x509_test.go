package x509policy

import (
	"crypto/x509"
	"net"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
)

func TestGuard_IsAllowed(t *testing.T) {
	type fields struct {
		permittedDNSDomains     []string
		excludedDNSDomains      []string
		permittedIPRanges       []*net.IPNet
		excludedIPRanges        []*net.IPNet
		permittedEmailAddresses []string
		excludedEmailAddresses  []string
		permittedURIDomains     []string
		excludedURIDomains      []string
	}
	tests := []struct {
		name    string
		fields  fields
		csr     *x509.CertificateRequest
		want    bool
		wantErr bool
	}{
		{
			name: "fail/dns-permitted",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			csr: &x509.CertificateRequest{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-excluded",
			fields: fields{
				excludedDNSDomains: []string{"example.com"},
			},
			csr: &x509.CertificateRequest{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv4-permitted",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("1.1.1.1")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv4-excluded",
			fields: fields{
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv6-permitted",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("3001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv6-excluded",
			fields: fields{
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
			},
			csr: &x509.CertificateRequest{
				EmailAddresses: []string{"mail@example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-excluded",
			fields: fields{
				excludedEmailAddresses: []string{"example.local"},
			},
			csr: &x509.CertificateRequest{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			csr: &x509.CertificateRequest{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-excluded",
			fields: fields{
				excludedURIDomains: []string{".example.local"},
			},
			csr: &x509.CertificateRequest{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name:   "ok/no-constraints",
			fields: fields{},
			csr: &x509.CertificateRequest{
				DNSNames: []string{"www.example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			csr: &x509.CertificateRequest{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.20")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7339")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
			},
			csr: &x509.CertificateRequest{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			csr: &x509.CertificateRequest{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-simple",
			fields: fields{
				permittedDNSDomains:     []string{".local"},
				permittedIPRanges:       []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				permittedEmailAddresses: []string{"example.local"},
				permittedURIDomains:     []string{".example.local"},
			},
			csr: &x509.CertificateRequest{
				DNSNames:       []string{"example.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
				EmailAddresses: []string{"mail@example.local"},
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.local",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		// TODO: more complex uses cases that combine multiple names
		// TODO: check errors (reasons) are as expected
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &NamePolicyEngine{
				permittedDNSDomains:     tt.fields.permittedDNSDomains,
				excludedDNSDomains:      tt.fields.excludedDNSDomains,
				permittedIPRanges:       tt.fields.permittedIPRanges,
				excludedIPRanges:        tt.fields.excludedIPRanges,
				permittedEmailAddresses: tt.fields.permittedEmailAddresses,
				excludedEmailAddresses:  tt.fields.excludedEmailAddresses,
				permittedURIDomains:     tt.fields.permittedURIDomains,
				excludedURIDomains:      tt.fields.excludedURIDomains,
			}
			got, err := g.AreCSRNamesAllowed(tt.csr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Guard.IsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.NotEquals(t, "", err.Error()) // TODO(hs): make this a complete equality check
			}
			if got != tt.want {
				t.Errorf("Guard.IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
