package x509policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
)

func TestNamePolicyEngine_AreCertificateNamesAllowed(t *testing.T) {
	// TODO(hs): refactor these tests into using validateNames instead of AreCertificateNamesAllowed
	// TODO(hs): the functionality in the policy engine is a nice candidate for trying fuzzing on
	type fields struct {
		verifySubjectCommonName bool
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
		cert    *x509.Certificate
		want    bool
		wantErr bool
	}{
		{
			name: "fail/dns-permitted",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-single-host",
			fields: fields{
				permittedDNSDomains: []string{"host.local"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"differenthost.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-no-label",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-empty-label",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www..local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-excluded",
			fields: fields{
				excludedDNSDomains: []string{"example.com"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-excluded-single-host",
			fields: fields{
				excludedDNSDomains: []string{"example.com"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.com"},
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
			cert: &x509.Certificate{
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
			cert: &x509.Certificate{
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
			cert: &x509.Certificate{
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
			cert: &x509.Certificate{
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
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-period-domain",
			fields: fields{
				permittedEmailAddresses: []string{".example.local"}, // any address in a domain, but not on the host example.local
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-excluded",
			fields: fields{
				excludedEmailAddresses: []string{"example.local"},
			},
			cert: &x509.Certificate{
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
			cert: &x509.Certificate{
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
			name: "fail/uri-permitted-period-host",
			fields: fields{
				permittedURIDomains: []string{".example.local"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-period-host-certificate",
			fields: fields{
				permittedURIDomains: []string{".example.local"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   ".example.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-empty-host",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-port-missing",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.local::",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-ip",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "127.0.0.1",
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
			cert: &x509.Certificate{
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
			name: "fail/subject-dns-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.notlocal",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-dns-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedDNSDomains:      []string{".local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-ipv4-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "10.10.10.10",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-ipv4-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-ipv6-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2002:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-ipv6-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2001:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-email-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedEmailAddresses: []string{"example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@smallstep.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-email-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedEmailAddresses:  []string{"example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-uri-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedURIDomains:     []string{".example.com"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.google.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-uri-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedURIDomains:      []string{".example.com"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/combined-simple-all-badhost.local",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
				permittedIPRanges:       []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				permittedEmailAddresses: []string{"example.local"},
				permittedURIDomains:     []string{".example.local"},
				excludedDNSDomains:      []string{"badhost.local"},
				excludedIPRanges:        []*net.IPNet{{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				excludedEmailAddresses:  []string{"badmail@example.local"},
				excludedURIDomains:      []string{"https://badwww.example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "badhost.local",
				},
				DNSNames:       []string{"example.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.130")},
				EmailAddresses: []string{"mail@example.local"},
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
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/empty-dns-constraint",
			fields: fields{
				permittedDNSDomains: []string{""},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-permitted",
			fields: fields{
				permittedDNSDomains: []string{".local"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-excluded",
			fields: fields{
				excludedDNSDomains: []string{".notlocal"},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4-permitted",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.20")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4-excluded",
			fields: fields{
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("10.10.10.10")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6-permitted",
			fields: fields{
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7339")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6-excluded",
			fields: fields{
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2003:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted",
			fields: fields{
				permittedEmailAddresses: []string{"example.local"},
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted-with-period-domain",
			fields: fields{
				permittedEmailAddresses: []string{".example.local"},
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@somehost.example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted-with-multiple-labels",
			fields: fields{
				permittedEmailAddresses: []string{".example.local"},
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@sub.www.example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded",
			fields: fields{
				excludedEmailAddresses: []string{"example.notlocal"},
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded-with-period-domain",
			fields: fields{
				excludedEmailAddresses: []string{".example.notlocal"},
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@somehost.example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-permitted",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			cert: &x509.Certificate{
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
			name: "ok/uri-permitted-with-port",
			fields: fields{
				permittedURIDomains: []string{".example.com"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com:8080",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-sub-permitted",
			fields: fields{
				permittedURIDomains: []string{"example.com"},
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "sub.host.example.com",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-excluded",
			fields: fields{
				excludedURIDomains: []string{".google.com"},
			},
			cert: &x509.Certificate{
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
			name: "ok/subject-empty",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-dns-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-dns-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedDNSDomains:      []string{".notlocal"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-ipv4-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.20",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-ipv4-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("128.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-ipv6-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2001:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-ipv6-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedIPRanges: []*net.IPNet{
					{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2009:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-email-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedEmailAddresses: []string{"example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-email-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedEmailAddresses:  []string{"example.notlocal"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-uri-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedURIDomains:     []string{".example.com"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-uri-excluded",
			fields: fields{
				verifySubjectCommonName: true,
				excludedURIDomains:      []string{".google.com"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-simple-permitted",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
				permittedIPRanges:       []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				permittedEmailAddresses: []string{"example.local"},
				permittedURIDomains:     []string{".example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "somehost.local",
				},
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
		{
			name: "ok/combined-simple-permitted-without-subject-verification",
			fields: fields{
				verifySubjectCommonName: false,
				permittedDNSDomains:     []string{".local"},
				permittedIPRanges:       []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				permittedEmailAddresses: []string{"example.local"},
				permittedURIDomains:     []string{".example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "forbidden-but-non-verified-domain.example.com",
				},
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
		{
			name: "ok/combined-simple-all",
			fields: fields{
				verifySubjectCommonName: true,
				permittedDNSDomains:     []string{".local"},
				permittedIPRanges:       []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				permittedEmailAddresses: []string{"example.local"},
				permittedURIDomains:     []string{".example.local"},
				excludedDNSDomains:      []string{"badhost.local"},
				excludedIPRanges:        []*net.IPNet{{IP: net.ParseIP("127.0.0.128"), Mask: net.IPv4Mask(255, 255, 255, 128)}},
				excludedEmailAddresses:  []string{"badmail@example.local"},
				excludedURIDomains:      []string{"https://badwww.example.local"},
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "somehost.local",
				},
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
		// TODO: more complex uses cases that combine multiple names and permitted/excluded entries
		// TODO: check errors (reasons) are as expected
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &NamePolicyEngine{
				verifySubjectCommonName: tt.fields.verifySubjectCommonName,
				permittedDNSDomains:     tt.fields.permittedDNSDomains,
				excludedDNSDomains:      tt.fields.excludedDNSDomains,
				permittedIPRanges:       tt.fields.permittedIPRanges,
				excludedIPRanges:        tt.fields.excludedIPRanges,
				permittedEmailAddresses: tt.fields.permittedEmailAddresses,
				excludedEmailAddresses:  tt.fields.excludedEmailAddresses,
				permittedURIDomains:     tt.fields.permittedURIDomains,
				excludedURIDomains:      tt.fields.excludedURIDomains,
			}
			got, err := g.AreCertificateNamesAllowed(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.NotEquals(t, "", err.Error()) // TODO(hs): make this a complete equality check
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
