package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/smallstep/assert"
	"golang.org/x/crypto/ssh"
)

// TODO(hs): the functionality in the policy engine is a nice candidate for trying fuzzing on
// TODO(hs): more complex use cases that combine multiple names and permitted/excluded entries

func TestNamePolicyEngine_matchDomainConstraint(t *testing.T) {
	tests := []struct {
		name                      string
		allowLiteralWildcardNames bool
		domain                    string
		constraint                string
		want                      bool
		wantErr                   bool
	}{
		{
			name:       "fail/wildcard",
			domain:     "host.local",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wildcard-literal",
			domain:     "*.example.com",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/specific-domain",
			domain:     "www.example.com",
			constraint: "host.example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/single-whitespace-domain",
			domain:     " ",
			constraint: "host.example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/period-domain",
			domain:     ".host.example.com",
			constraint: ".example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wrong-asterisk-prefix",
			domain:     "*Xexample.com",
			constraint: ".example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/asterisk-in-domain",
			domain:     "e*ample.com",
			constraint: ".com",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/asterisk-label",
			domain:     "example.*.local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/multiple-periods",
			domain:     "example.local",
			constraint: "..local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/error-parsing-domain",
			domain:     string(byte(0)),
			constraint: ".local",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "fail/error-parsing-constraint",
			domain:     "example.local",
			constraint: string(byte(0)),
			want:       false,
			wantErr:    true,
		},
		{
			name:       "fail/no-subdomain",
			domain:     "local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/too-many-subdomains",
			domain:     "www.example.local",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "fail/wrong-domain",
			domain:     "example.notlocal",
			constraint: ".local",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "false/idna-internationalized-domain-name",
			domain:     "JP納豆.例.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			constraint: ".例.jp",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "false/idna-internationalized-domain-name-constraint",
			domain:     "xn--jp-cd2fp15c.xn--fsq.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			constraint: ".例.jp",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "ok/empty-constraint",
			domain:     "www.example.com",
			constraint: "",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/wildcard",
			domain:     "www.example.com",
			constraint: ".example.com", // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:       true,
			wantErr:    false,
		},
		{
			name:                      "ok/wildcard-literal",
			allowLiteralWildcardNames: true,
			domain:                    "*.example.com", // specifically allowed using an option on the NamePolicyEngine
			constraint:                ".example.com",  // internally we're using the x509 period prefix as the indicator for exactly one subdomain
			want:                      true,
			wantErr:                   false,
		},
		{
			name:       "ok/specific-domain",
			domain:     "www.example.com",
			constraint: "www.example.com",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/different-case",
			domain:     "WWW.EXAMPLE.com",
			constraint: "www.example.com",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "ok/idna-internationalized-domain-name-punycode",
			domain:     "xn--jp-cd2fp15c.xn--fsq.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			constraint: ".xn--fsq.jp",
			want:       true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NamePolicyEngine{
				allowLiteralWildcardNames: tt.allowLiteralWildcardNames,
			}
			got, err := engine.matchDomainConstraint(tt.domain, tt.constraint)
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
		{
			name:   "ok/different-case",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "EXAMPLE.com",
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
		{
			name:   "ok/different-case",
			engine: &NamePolicyEngine{},
			uri: &url.URL{
				Scheme: "https",
				Host:   "www.EXAMPLE.local",
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

func extractSANs(cert *x509.Certificate, includeSubject bool) []string {
	sans := []string{}
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	if includeSubject && cert.Subject.CommonName != "" {
		sans = append(sans, cert.Subject.CommonName)
	}
	return sans
}

func TestNamePolicyEngine_X509_AllAllowed(t *testing.T) {
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
			name: "fail/dns-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.豆.jp"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					string(byte(0)) + ".例.jp",
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
			name: "fail/mail-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"bücher@例.jp"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-idna-internationalized-domain-rfc822",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"bücher@例.jp" + string(byte(0))},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/mail-permitted-idna-internationalized-domain-ascii",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@xn---bla.jp"},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/uri-permitted-domain-wildcard",
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
			name: "fail/uri-permitted",
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
			name: "fail/uri-permitted-with-literal-wildcard", // don't allow literal wildcard in URI, e.g. xxxx://*.domain.tld
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
		{
			name: "fail/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "abc.bücher.example.com",
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
		{
			name: "fail/uri-excluded-with-literal-wildcard", // don't allow literal wildcard in URI, e.g. xxxx://*.domain.tld
			options: []NamePolicyOption{
				AddExcludedURIDomain("*.local"),
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
			name: "ok/dns-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedDNSDomain("*.例.jp"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"JP納豆.例.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
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
			name: "ok/mail-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedEmailAddress("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{},
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
		{
			name: "ok/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedURIDomain("*.bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "abc.xn--bcher-kva.example.com",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				AddPermittedURIDomain("bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "xn--bcher-kva.example.com",
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
			got, err := engine.AreCertificateNamesAllowed(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.NotEquals(t, "", err.Error()) // TODO(hs): implement a more specific error comparison?
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.AreCertificateNamesAllowed() = %v, want %v", got, tt.want)
			}

			// Perform the same tests for a CSR, which are similar to Certificates
			csr := &x509.CertificateRequest{
				Subject:        tt.cert.Subject,
				DNSNames:       tt.cert.DNSNames,
				EmailAddresses: tt.cert.EmailAddresses,
				IPAddresses:    tt.cert.IPAddresses,
				URIs:           tt.cert.URIs,
			}
			got, err = engine.AreCSRNamesAllowed(csr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.AreCSRNamesAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.NotEquals(t, "", err.Error())
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.AreCSRNamesAllowed() = %v, want %v", got, tt.want)
			}

			// Perform the same tests for a slice of SANs
			includeSubject := engine.verifySubjectCommonName // copy behavior of the engine when Subject has to be included as a SAN
			sans := extractSANs(tt.cert, includeSubject)
			got, err = engine.AreSANsAllowed(sans)
			if (err != nil) != tt.wantErr {
				t.Errorf("NamePolicyEngine.AreSANsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.NotEquals(t, "", err.Error())
			}
			if got != tt.want {
				t.Errorf("NamePolicyEngine.AreSANsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamePolicyEngine_SSH_ArePrincipalsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		options []NamePolicyOption
		cert    *ssh.Certificate
		want    bool
		wantErr bool
	}{
		{
			name: "fail/host-with-permitted-dns-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.example.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-with-excluded-dns-domain",
			options: []NamePolicyOption{
				WithExcludedDNSDomain("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-with-permitted-ip",
			options: []NamePolicyOption{
				WithPermittedCIDR("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"192.168.0.22",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-with-excluded-ip",
			options: []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"127.0.0.0",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-with-permitted-email",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@local",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-with-excluded-email",
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@example.com",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals([]string{"localhost"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals([]string{"localhost"}),
			},
			cert: &ssh.Certificate{
				ValidPrincipals: []string{
					"localhost",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals([]string{"user"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"root",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals([]string{"user"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-with-permitted-principal-as-mail",
			options: []NamePolicyOption{
				WithPermittedPrincipals([]string{"ops"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"ops@work", // this is (currently) parsed as an email-like principal; not allowed with just "ops" as the permitted principal
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-principal-with-permitted-dns-domain", // when only DNS is permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/host-principal-with-permitted-ip-range", // when only IPs are permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedCIDR("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/user-principal-with-permitted-email", // when only emails are permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/combined-user",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@smallstep.com"),
				WithExcludedEmailAddress("root@smallstep.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "fail/combined-user-with-excluded-user-principal",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@smallstep.com"),
				WithExcludedPrincipals([]string{"root"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"root",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ok/host-with-permitted-user-principals",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@work"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"example.work",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ok/user-with-permitted-user-principals",
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"herman@work",
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ok/host-with-permitted-dns-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/host-with-excluded-dns-domain",
			options: []NamePolicyOption{
				WithExcludedDNSDomain("*.example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/host-with-permitted-ip",
			options: []NamePolicyOption{
				WithPermittedCIDR("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"127.0.0.33",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/host-with-excluded-ip",
			options: []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"192.168.0.35",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/user-with-permitted-email",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@example.com",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/user-with-excluded-email",
			options: []NamePolicyOption{
				WithExcludedEmailAddress("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@local",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/user-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals([]string{"*"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/user-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals([]string{"user"}),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"root",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-user",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@smallstep.com"),
				WithPermittedPrincipals([]string{"*"}), // without specifying the wildcard, "someone" would not be allowed.
				WithExcludedEmailAddress("root@smallstep.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-user-with-excluded-user-principal",
			options: []NamePolicyOption{
				WithPermittedEmailAddress("@smallstep.com"),
				WithExcludedEmailAddress("root@smallstep.com"),
				WithExcludedPrincipals([]string{"root"}), // unlike the previous test, this implicitly allows any other username principal
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ok/combined-host",
			options: []NamePolicyOption{
				WithPermittedDNSDomain("*.local"),
				WithPermittedCIDR("127.0.0.1/24"),
				WithExcludedDNSDomain("badhost.local"),
				WithExcludedCIDR("127.0.0.128/25"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"example.local",
					"127.0.0.31",
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
			got, err := engine.ArePrincipalsAllowed(tt.cert)
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

type result struct {
	wantDNSNames  []string
	wantIps       []net.IP
	wantEmails    []string
	wantUsernames []string
}

func emptyResult() result {
	return result{
		wantDNSNames:  []string{},
		wantIps:       []net.IP{},
		wantEmails:    []string{},
		wantUsernames: []string{},
	}
}

func Test_splitSSHPrincipals(t *testing.T) {
	type test struct {
		cert    *ssh.Certificate
		r       result
		wantErr bool
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unexpected-cert-type": func(t *testing.T) test {
			r := emptyResult()
			return test{
				cert: &ssh.Certificate{
					CertType: uint32(0),
				},
				r:       r,
				wantErr: true,
			}
		},
		"fail/user-uri": func(t *testing.T) test {
			r := emptyResult()
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"https://host.local/"},
				},
				r:       r,
				wantErr: true,
			}
		},
		"fail/host-uri": func(t *testing.T) test {
			r := emptyResult()
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.HostCert,
					ValidPrincipals: []string{"https://host.local/"},
				},
				r:       r,
				wantErr: true,
			}
		},
		"ok/host-dns": func(t *testing.T) test {
			r := emptyResult()
			r.wantDNSNames = []string{"host.example.com"}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.HostCert,
					ValidPrincipals: []string{"host.example.com"},
				},
				r: r,
			}
		},
		"ok/host-ip": func(t *testing.T) test {
			r := emptyResult()
			r.wantIps = []net.IP{net.ParseIP("127.0.0.1")}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.HostCert,
					ValidPrincipals: []string{"127.0.0.1"},
				},
				r: r,
			}
		},
		"ok/host-email": func(t *testing.T) test {
			r := emptyResult()
			r.wantEmails = []string{"ops@work"}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.HostCert,
					ValidPrincipals: []string{"ops@work"},
				},
				r:       r,
				wantErr: false,
			}
		},
		"ok/user-localhost": func(t *testing.T) test {
			r := emptyResult()
			r.wantUsernames = []string{"localhost"} // when type is User cert, this is considered a username; not a DNS
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"localhost"},
				},
				r: r,
			}
		},
		"ok/user-username-with-period": func(t *testing.T) test {
			r := emptyResult()
			r.wantUsernames = []string{"x.joe"}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"x.joe"},
				},
				r: r,
			}
		},
		"ok/user-ip": func(t *testing.T) test {
			r := emptyResult()
			r.wantIps = []net.IP{net.ParseIP("127.0.0.1")}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"127.0.0.1"},
				},
				r:       r,
				wantErr: false,
			}
		},
		"ok/user-maillike": func(t *testing.T) test {
			r := emptyResult()
			r.wantEmails = []string{"ops@work"}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"ops@work"},
				},
				r: r,
			}
		},
	}
	for name, prep := range tests {
		tt := prep(t)
		t.Run(name, func(t *testing.T) {
			gotDNSNames, gotIps, gotEmails, gotUsernames, err := splitSSHPrincipals(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitSSHPrincipals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(tt.r.wantDNSNames, gotDNSNames) {
				t.Errorf("splitSSHPrincipals() DNS names diff =\n%s", cmp.Diff(tt.r.wantDNSNames, gotDNSNames))
			}
			if !cmp.Equal(tt.r.wantIps, gotIps) {
				t.Errorf("splitSSHPrincipals() IPs diff =\n%s", cmp.Diff(tt.r.wantIps, gotIps))
			}
			if !cmp.Equal(tt.r.wantEmails, gotEmails) {
				t.Errorf("splitSSHPrincipals() Emails diff =\n%s", cmp.Diff(tt.r.wantEmails, gotEmails))
			}
			if !cmp.Equal(tt.r.wantUsernames, gotUsernames) {
				t.Errorf("splitSSHPrincipals() Usernames diff =\n%s", cmp.Diff(tt.r.wantUsernames, gotUsernames))
			}
		})
	}
}
