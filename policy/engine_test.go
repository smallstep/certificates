package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
)

// TODO(hs): the functionality in the policy engine is a nice candidate for trying fuzzing on
// TODO(hs): more complex uses cases that combine multiple names and permitted/excluded entries
// TODO(hs): check errors (reasons) are as expected

func TestNamePolicyEngine_matchDomainConstraint(t *testing.T) {
	tests := []struct {
		name       string
		engine     *NamePolicyEngine
		domain     string
		constraint string
		want       bool
		wantErr    bool
	}{
		{
			name:       "fail/wildcard",
			engine:     &NamePolicyEngine{},
			domain:     "host.local",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wildcard-literal",
			engine:     &NamePolicyEngine{},
			domain:     "*.example.com",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/specific-domain",
			engine:     &NamePolicyEngine{},
			domain:     "www.example.com",
			constraint: "host.example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/single-whitespace-domain",
			engine:     &NamePolicyEngine{},
			domain:     " ",
			constraint: "host.example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/period-domain",
			engine:     &NamePolicyEngine{},
			domain:     ".host.example.com",
			constraint: ".example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wrong-asterisk-prefix",
			engine:     &NamePolicyEngine{},
			domain:     "*Xexample.com",
			constraint: ".example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/asterisk-in-domain",
			engine:     &NamePolicyEngine{},
			domain:     "e*ample.com",
			constraint: ".com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/asterisk-label",
			engine:     &NamePolicyEngine{},
			domain:     "example.*.local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/multiple-periods",
			engine:     &NamePolicyEngine{},
			domain:     "example.local",
			constraint: "..local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/error-parsing-domain",
			engine:     &NamePolicyEngine{},
			domain:     string([]byte{0}),
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "fail/error-parsing-constraint",
			engine:     &NamePolicyEngine{},
			domain:     "example.local",
			constraint: string([]byte{0}),
			want:       false,
			wantErr:    true,
		},
		{
			name:       "fail/no-subdomain",
			engine:     &NamePolicyEngine{},
			domain:     "local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/too-many-subdomains",
			engine:     &NamePolicyEngine{},
			domain:     "www.example.local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wrong-domain",
			engine:     &NamePolicyEngine{},
			domain:     "example.notlocal",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "ok/empty-constraint",
			engine:     &NamePolicyEngine{},
			domain:     "www.example.com",
			constraint: "",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/wildcard",
			engine:     &NamePolicyEngine{},
			domain:     "www.example.com",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       true,
			wantErr:    false,
		},
		{
			name: "ok/wildcard-literal",
			engine: &NamePolicyEngine{
				allowLiteralWildcardNames: true,
			},
			domain:     "*.example.com", // specifically allowed using an option on the NamePolicyEngine
			constraint: ".example.com",  // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/specific-domain",
			engine:     &NamePolicyEngine{},
			domain:     "www.example.com",
			constraint: "www.example.com",
			want:       true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.engine.matchDomainConstraint(tt.domain, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.matchDomainConstraint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.matchDomainConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_matchIPConstraint(t *testing.T) {
	nat64IP, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	assert.FatalError(t, err)
	tests := []struct {
		name       string
		ip         net.IP
		constraint *net.IPNet
		want       bool
		wantErr    bool
	}{
		{
			name:       "false/ipv4-in-ipv6-nat64",
			ip:         net.ParseIP("192.0.2.128"),
			constraint: nat64Net,
			want:       false,
			wantErr:    false,
		},
		{
			name: "ok/ipv4",
			ip:   net.ParseIP("127.0.0.1"),
			constraint: &net.IPNet{
				IP:   net.ParseIP("127.0.0.0"),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6",
			ip:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7335"),
			constraint: &net.IPNet{
				IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				Mask: net.CIDRMask(120, 128),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4-in-ipv6", // ipv4 in ipv6 addresses are considered the same in the current implementation, because Go parses them as IPv4
			ip:   net.ParseIP("::ffff:192.0.2.128"),
			constraint: &net.IPNet{
				IP:   net.ParseIP("192.0.2.0"),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			want:    true,
			wantErr: false,
		},
		{
			name:       "ok/ipv4-in-ipv6-nat64-fixed-ip",
			ip:         nat64IP,
			constraint: nat64Net,
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/ipv4-in-ipv6-nat64",
			ip:         net.ParseIP("64:ff9b::192.0.2.129"),
			constraint: nat64Net,
			want:       true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchIPConstraint(tt.ip, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchIPConstraint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("matchIPConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamePolicyEngine_matchEmailConstraint(t *testing.T) {

	tests := []struct {
		name       string
		engine     *NamePolicyEngine
		mailbox    rfc2821Mailbox
		constraint string
		want       bool
		wantErr    bool
	}{
		{
			name:   "fail/asterisk-prefix",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "*@example.com",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/asterisk-label",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "@host.*.example.com",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/asterisk-inside-local",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "m*il@local",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/asterisk-inside-domain",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "@h*st.example.com",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/parse-email",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "@example.com",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/wildcard",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:   "fail/wildcard-x509-period",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: ".local", // "wildcard" for the local domain; requires exactly 1 subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:   "fail/specific-mail-wrong-domain",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "mail@example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:   "fail/specific-mail-wrong-local",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "root",
				domain: "example.com",
			},
			constraint: "mail@example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:   "ok/wildcard",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "local", // "wildcard" for the local domain
			want:       true,
			wantErr:    false,
		},
		{
			name:   "ok/wildcard-x509-period",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "example.local",
			},
			constraint: ".local", // "wildcard" for the local domain; requires exactly 1 subdomain
			want:       true,
			wantErr:    false,
		},
		{
			name:   "ok/specific-mail",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "mail@local",
			want:       true,
			wantErr:    false,
		},
		{
			name:   "ok/wildcard-tld",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "example.com",
			},
			constraint: "example.com", // "wildcard" for 'example.com'
			want:       true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.engine.matchEmailConstraint(tt.mailbox, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.matchEmailConstraint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.matchEmailConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamePolicyEngine_matchURIConstraint(t *testing.T) {
	tests := []struct {
		name       string
		engine     *NamePolicyEngine
		uri        *url.URL
		constraint string
		want       bool
		wantErr    bool
	}{
		{
			name:   "fail/empty-host",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "",
			},
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/host-with-asterisk-prefix",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "*.local",
			},
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/host-with-asterisk-label",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "host.*.local",
			},
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/host-with-asterisk-inside",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "h*st.local",
			},
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/wildcard",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.example.notlocal",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:   "fail/wildcard-subdomains-too-deep",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.sub.example.local",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:   "fail/host-with-port-split-error",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.example.local::8080",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/host-with-ipv4",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "127.0.0.1",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       false,
			wantErr:    true,
		},
		{
			name:   "fail/host-with-ipv6",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       false,
			wantErr:    true,
		},
		{
			name:   "ok/wildcard",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.example.local",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       true,
			wantErr:    false,
		},
		{
			name:   "ok/host-with-port",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.example.local:8080",
			},
			constraint: ".example.local", // using x509 period as the "wildcard"; expects a single subdomain
			want:       true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.engine.matchURIConstraint(tt.uri, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.matchURIConstraint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.matchURIConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamePolicyEngine_AreCertificateNamesAllowed(t *testing.T) {
	tests := []struct {
		name    string
		options []NamePolicyOption
		cert    *x509.Certificate
		want    bool
		wantErr bool
	}{
		// SINGLE SAN TYPE PERMITTED FAILURE TESTS
		{
			name: "fail/dns-permitted",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-wildcard-literal-x509",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.x509local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.x509local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-single-host",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("host.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"differenthost.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-no-label",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-empty-label",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www..local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-dot-domain",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					".local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-wildcard-multiple-subdomains",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"sub.example.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-wildcard-literal",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv4-permitted",
			options: []NamePolicyOption{
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("1.1.1.1")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv6-permitted",
			options: []NamePolicyOption{
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("3001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-wildcard",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-wildcard-x509",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-specific-mailbox",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("test@local.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"root@local.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-wildcard-subdomain",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@sub.example.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/permitted-uri-domain-wildcard",
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.com",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/permitted-uri",
			options: []NamePolicyOption{
				AddPermittedURIDomain("test.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "bad.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/permitted-uri-with-literal-wildcard", // don't allow literal wildcard in URI, e.g. xxxx://*.domain.tld
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "*.local",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		// SINGLE SAN TYPE EXCLUDED FAILURE TESTS
		{
			name: "fail/dns-excluded",
			options: []NamePolicyOption{
				AddExcludedDNSDomain("*.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-excluded-single-host",
			options: []NamePolicyOption{
				AddExcludedDNSDomain("host.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"host.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv4-excluded",
			options: []NamePolicyOption{
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ipv6-excluded",
			options: []NamePolicyOption{
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-excluded",
			options: []NamePolicyOption{
				AddExcludedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-excluded",
			options: []NamePolicyOption{
				AddExcludedURIDomain("*.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		// SUBJECT FAILURE TESTS
		{
			name: "fail/subject-dns-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedDNSDomain("*.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedDNSDomain("*.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.30",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/subject-ipv6-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedEmailAddress("@example.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedEmailAddress("@example.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedURIDomain("*.example.com"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedURIDomain("*.example.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		// DIFFERENT SAN PERMITTED FAILURE TESTS
		{
			name: "fail/dns-permitted-with-ip-name", // when only DNS is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-with-mail", // when only DNS is permitted, mails are not allowed.
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/dns-permitted-with-uri", // when only DNS is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ip-permitted-with-dns-name", // when only IP is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ip-permitted-with-mail", // when only IP is permitted, mails are not allowed.
			options: []NamePolicyOption{
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/ip-permitted-with-uri", // when only IP is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-with-dns-name", // when only mail is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-with-ip", // when only mail is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-with-uri", // when only mail is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-with-dns-name", // when only URI is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"host.local"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-with-ip-name", // when only URI is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-with-ip-name", // when only URI is permitted, mails are not allowed.
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want:    false,
			wantErr: true,
		},
		// COMBINED FAILURE TESTS
		{
			name: "fail/combined-simple-all-badhost.local",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomain("*.local"),
				WithPermittedCIDR("127.0.0.1/24"),
				WithPermittedEmailAddress("@example.local"),
				WithPermittedURIDomain("*.example.local"),
				WithExcludedDNSDomain("badhost.local"),
				WithExcludedCIDR("127.0.0.128/25"),
				WithExcludedEmailAddress("badmail@example.local"),
				WithExcludedURIDomain("badwww.example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "badhost.local",
				},
				DNSNames:       []string{"example.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.40")},
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
		// NO CONSTRAINT SUCCESS TESTS
		{
			name:    "ok/dns-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name:    "ok/ipv4-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name:    "ok/ipv6-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name:    "ok/mail-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name:    "ok/uri-no-constraints",
			options: []NamePolicyOption{},
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
			name: "ok/subject-no-constraints",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "www.example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/subject-empty-no-constraints",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
			},
			want:    true,
			wantErr: false,
		},
		// SINGLE SAN TYPE PERMITTED SUCCESS TESTS
		{
			name: "ok/dns-permitted",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-permitted-wildcard",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
				AddPermittedDNSDomain(".x509local"),
				WithAllowLiteralWildcardNames(),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"host.local",
					"test.x509local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/empty-dns-constraint",
			options: []NamePolicyOption{
				AddPermittedDNSDomain(""),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-permitted-wildcard-literal",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
				AddPermittedDNSDomain("*.x509local"),
				WithAllowLiteralWildcardNames(),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.local",
					"*.x509local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-permitted-combined",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.local"),
				AddPermittedDNSDomain("*.x509local"),
				AddPermittedDNSDomain("host.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"example.local",
					"example.x509local",
					"host.example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4-permitted",
			options: []NamePolicyOption{
				AddPermittedCIDR("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.20")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6-permitted",
			options: []NamePolicyOption{
				AddPermittedCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7339")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted-wildcard",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted-plain-domain",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-permitted-specific-mailbox",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("test@local.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-permitted-domain-wildcard",
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.local",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-permitted-specific-uri",
			options: []NamePolicyOption{
				AddPermittedURIDomain("test.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "test.local",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-permitted-with-port",
			options: []NamePolicyOption{
				AddPermittedURIDomain(".example.com"),
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
		// SINGLE SAN TYPE EXCLUDED SUCCESS TESTS
		{
			name: "ok/dns-excluded",
			options: []NamePolicyOption{
				WithExcludedDNSDomain("*.notlocal"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv4-excluded",
			options: []NamePolicyOption{
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("10.10.10.10")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ipv6-excluded",
			options: []NamePolicyOption{
				AddExcludedCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2003:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded",
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@notlocal"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded-with-subdomain",
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-excluded",
			options: []NamePolicyOption{
				WithExcludedURIDomain("*.google.com"),
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
		// SUBJECT SUCCESS TESTS
		{
			name: "ok/subject-empty",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedDNSDomain("*.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedDNSDomain("*.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedDNSDomain("*.notlocal"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("127.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("128.0.0.1"),
							Mask: net.IPv4Mask(255, 255, 255, 0),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedIPRanges(
					[]*net.IPNet{
						{
							IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							Mask: net.CIDRMask(120, 128),
						},
					},
				),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedEmailAddress("@example.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedEmailAddress("@example.notlocal"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddPermittedURIDomain("*.example.com"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedURIDomain("*.smallstep.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		// DIFFERENT SAN TYPE EXCLUDED SUCCESS TESTS
		{
			name: "ok/dns-excluded-with-ip-name", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				AddExcludedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-excluded-with-mail", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				AddExcludedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-excluded-with-mail", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				AddExcludedDNSDomain("*.local"),
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
			name: "ok/ip-excluded-with-dns", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ip-excluded-with-mail", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/ip-excluded-with-mail", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
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
			name: "ok/mail-excluded-with-dns", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded-with-ip", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@example.com"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/mail-excluded-with-uri", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@example.com"),
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
			name: "ok/uri-excluded-with-dns", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomain("*.example.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-excluded-with-dns", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomain("*.example.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-excluded-with-mail", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomain("*.example.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/dns-excluded-with-subject-ip-name", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				AddExcludedDNSDomain("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want:    true,
			wantErr: false,
		},
		// COMBINED SUCCESS TESTS
		{
			name: "ok/combined-simple-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomain("*.local"),
				WithPermittedCIDR("127.0.0.1/24"),
				WithPermittedEmailAddress("@example.local"),
				WithPermittedURIDomain("*.example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "somehost.local",
				},
				DNSNames:       []string{"example.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.15")},
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
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
				WithPermittedCIDR("127.0.0.1/24"),
				WithPermittedEmailAddress("@example.local"),
				WithPermittedURIDomain("*.example.local"),
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
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomain("*.local"),
				WithPermittedCIDR("127.0.0.1/24"),
				WithPermittedEmailAddress("@example.local"),
				WithPermittedURIDomain("*.example.local"),
				WithExcludedDNSDomain("badhost.local"),
				WithExcludedCIDR("127.0.0.128/25"),
				WithExcludedEmailAddress("badmail@example.local"),
				WithExcludedURIDomain("badwww.example.local"),
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := New(tt.options...)
			assert.FatalError(t, err)
			got, err := engine.AreCertificateNamesAllowed(tt.cert) // TODO: perform tests on CSR, sans, etc. too
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
