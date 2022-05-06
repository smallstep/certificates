package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

// TODO(hs): the functionality in the policy engine is a nice candidate for trying fuzzing on
// TODO(hs): more complex test use cases that combine multiple names and permitted/excluded entries?

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
	assert.NoError(t, err)
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
			constraint: ".local",
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
			name:   "ok/asterisk-prefix",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "*@example.com",
			want:       false,
			wantErr:    false,
		},
		{
			name:   "ok/asterisk-prefix-match",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "*",
				domain: "example.com",
			},
			constraint: "*@example.com",
			want:       true,
			wantErr:    false,
		},
		{
			name:   "ok/asterisk-inside-local",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "mail",
				domain: "local",
			},
			constraint: "m*il@local",
			want:       false,
			wantErr:    false,
		},
		{
			name:   "ok/asterisk-inside-local-match",
			engine: &NamePolicyEngine{},
			mailbox: rfc2821Mailbox{
				local:  "m*il",
				domain: "local",
			},
			constraint: "m*il@local",
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

func TestNamePolicyEngine_X509_AllAllowed(t *testing.T) {
	tests := []struct {
		name    string
		options []NamePolicyOption
		cert    *x509.Certificate
		want    bool
		wantErr *NamePolicyError
	}{
		// SINGLE SAN TYPE PERMITTED FAILURE TESTS
		{
			name: "fail/dns-permitted",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
		},
		{
			name: "fail/dns-permitted-wildcard-literal-x509",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.x509local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.x509local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "*.x509local",
			},
		},
		{
			name: "fail/dns-permitted-single-host",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("host.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"differenthost.local"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "differenthost.local",
			},
		},
		{
			name: "fail/dns-permitted-no-label",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"local"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "local",
			},
		},
		{
			name: "fail/dns-permitted-empty-label",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www..local"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: DNSNameType,
				Name:     "www..local",
			},
		},
		{
			name: "fail/dns-permitted-dot-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					".local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     ".local",
			},
		},
		{
			name: "fail/dns-permitted-wildcard-multiple-subdomains",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"sub.example.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "sub.example.local",
			},
		},
		{
			name: "fail/dns-permitted-wildcard-literal",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "*.local",
			},
		},
		{
			name: "fail/dns-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.豆.jp"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					string(byte(0)) + ".例.jp",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: DNSNameType,
				Name:     string(byte(0)) + ".例.jp",
			},
		},
		{
			name: "fail/ipv4-permitted",
			options: []NamePolicyOption{
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("1.1.1.1")},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "1.1.1.1",
			},
		},
		{
			name: "fail/ipv6-permitted",
			options: []NamePolicyOption{
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("3001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "3001:db8:85a3::8a2e:370:7334", // IPv6 is shortened internally
			},
		},
		{
			name: "fail/mail-permitted-wildcard",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "test@local.com",
			},
		},
		{
			name: "fail/mail-permitted-wildcard-x509",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "test@local.com",
			},
		},
		{
			name: "fail/mail-permitted-specific-mailbox",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("test@local.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"root@local.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "root@local.com",
			},
		},
		{
			name: "fail/mail-permitted-wildcard-subdomain",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@sub.example.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "test@sub.example.com",
			},
		},
		{
			name: "fail/mail-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"bücher@例.jp"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseRFC822Name,
				NameType: EmailNameType,
				Name:     "bücher@例.jp",
			},
		},
		{
			name: "fail/mail-permitted-idna-internationalized-domain-rfc822",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"bücher@例.jp" + string(byte(0))},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseRFC822Name,
				NameType: EmailNameType,
				Name:     "bücher@例.jp" + string(byte(0)),
			},
		},
		{
			name: "fail/mail-permitted-idna-internationalized-domain-ascii",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@xn---bla.jp"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: EmailNameType,
				Name:     "mail@xn---bla.jp",
			},
		},
		{
			name: "fail/uri-permitted-domain-wildcard",
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.com",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://example.com",
			},
		},
		{
			name: "fail/uri-permitted",
			options: []NamePolicyOption{
				WithPermittedURIDomains("test.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "bad.local",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://bad.local",
			},
		},
		{
			name: "fail/uri-permitted-with-literal-wildcard", // don't allow literal wildcard in URI, e.g. xxxx://*.domain.tld
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "*.local",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotMatchNameToConstraint,
				NameType: URINameType,
				Name:     "https://*.local",
			},
		},
		{
			name: "fail/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "abc.bücher.example.com",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotMatchNameToConstraint,
				NameType: URINameType,
				Name:     "https://abc.b%C3%BCcher.example.com",
			},
		},
		// SINGLE SAN TYPE EXCLUDED FAILURE TESTS
		{
			name: "fail/dns-excluded",
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
		},
		{
			name: "fail/dns-excluded-single-host",
			options: []NamePolicyOption{
				WithExcludedDNSDomains("host.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"host.example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "host.example.com",
			},
		},
		{
			name: "fail/ipv4-excluded",
			options: []NamePolicyOption{
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "127.0.0.1",
			},
		},
		{
			name: "fail/ipv6-excluded",
			options: []NamePolicyOption{
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "2001:db8:85a3::8a2e:370:7334",
			},
		},
		{
			name: "fail/mail-excluded",
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@example.com",
			},
		},
		{
			name: "fail/uri-excluded",
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://www.example.com",
			},
		},
		{
			name: "fail/uri-excluded-with-literal-wildcard", // don't allow literal wildcard in URI, e.g. xxxx://*.domain.tld
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "*.local",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotMatchNameToConstraint,
				NameType: URINameType,
				Name:     "https://*.local",
			},
		},
		// SUBJECT FAILURE TESTS
		{
			name: "fail/subject-permitted-no-match",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedCommonNames("this name is allowed", "and this one too"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "some certificate name",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed, // only permitted names allowed
				NameType: CNNameType,
				Name:     "some certificate name",
			},
		},
		{
			name: "fail/subject-excluded-match",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedCommonNames("this name is not allowed"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "this name is not allowed",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseDomain, // CN cannot be parsed as DNS in this case
				NameType: CNNameType,
				Name:     "this name is not allowed",
			},
		},
		{
			name: "fail/subject-dns-no-domain",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "name with space.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: CNNameType,
				Name:     "name with space.local",
			},
		},
		{
			name: "fail/subject-dns-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.notlocal",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "example.notlocal",
			},
		},
		{
			name: "fail/subject-dns-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "example.local",
			},
		},
		{
			name: "fail/subject-ipv4-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "10.10.10.10",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "10.10.10.10",
			},
		},
		{
			name: "fail/subject-ipv4-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.30",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "127.0.0.30",
			},
		},
		{
			name: "fail/subject-ipv6-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2002:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "2002:db8:85a3::8a2e:370:7339",
			},
		},
		{
			name: "fail/subject-ipv6-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2001:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "2001:db8:85a3::8a2e:370:7339",
			},
		},
		{
			name: "fail/subject-email-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedEmailAddresses("@example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@smallstep.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "mail@smallstep.com",
			},
		},
		{
			name: "fail/subject-email-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedEmailAddresses("@example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "mail@example.local",
			},
		},
		{
			name: "fail/subject-uri-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedURIDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.google.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "https://www.google.com",
			},
		},
		{
			name: "fail/subject-uri-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedURIDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "https://www.example.com",
			},
		},
		// DIFFERENT SAN PERMITTED FAILURE TESTS
		{
			name: "fail/dns-permitted-with-ip-name", // when only DNS is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "127.0.0.1",
			},
		},
		{
			name: "fail/dns-permitted-with-mail", // when only DNS is permitted, mails are not allowed.
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@smallstep.com",
			},
		},
		{
			name: "fail/dns-permitted-with-uri", // when only DNS is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://www.example.com",
			},
		},
		{
			name: "fail/ip-permitted-with-dns-name", // when only IP is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
		},
		{
			name: "fail/ip-permitted-with-mail", // when only IP is permitted, mails are not allowed.
			options: []NamePolicyOption{
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@smallstep.com",
			},
		},
		{
			name: "fail/ip-permitted-with-uri", // when only IP is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
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
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://www.example.com",
			},
		},
		{
			name: "fail/mail-permitted-with-dns-name", // when only mail is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
		},
		{
			name: "fail/mail-permitted-with-ip", // when only mail is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "127.0.0.1",
			},
		},
		{
			name: "fail/mail-permitted-with-uri", // when only mail is permitted, URIs are not allowed.
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     "https://www.example.com",
			},
		},
		{
			name: "fail/uri-permitted-with-dns-name", // when only URI is permitted, DNS names are not allowed.
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"host.local"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "host.local",
			},
		},
		{
			name: "fail/uri-permitted-with-ip-name", // when only URI is permitted, IPs are not allowed.
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "2001:db8:85a3::8a2e:370:7334",
			},
		},
		{
			name: "fail/uri-permitted-with-ip-name", // when only URI is permitted, mails are not allowed.
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@smallstep.com",
			},
		},
		// COMBINED FAILURE TESTS
		{
			name: "fail/combined-simple-all-badhost.local-common-name",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
				WithExcludedDNSDomains("badhost.local"),
				WithExcludedCIDRs("127.0.0.128/25"),
				WithExcludedEmailAddresses("badmail@example.local"),
				WithExcludedURIDomains("badwww.example.local"),
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
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: CNNameType,
				Name:     "badhost.local",
			},
		},
		{
			name: "fail/combined-simple-all-anotherbadhost.local-dns",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
				WithExcludedDNSDomains("anotherbadhost.local"),
				WithExcludedCIDRs("127.0.0.128/25"),
				WithExcludedEmailAddresses("badmail@example.local"),
				WithExcludedURIDomains("badwww.example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "badhost.local",
				},
				DNSNames:       []string{"anotherbadhost.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.40")},
				EmailAddresses: []string{"mail@example.local"},
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.local",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "anotherbadhost.local",
			},
		},
		{
			name: "fail/combined-simple-all-badmail@example.local",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
				WithExcludedDNSDomains("badhost.local"),
				WithExcludedCIDRs("127.0.0.128/25"),
				WithExcludedEmailAddresses("badmail@example.local"),
				WithExcludedURIDomains("badwww.example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "badhost.local",
				},
				DNSNames:       []string{"example.local"},
				IPAddresses:    []net.IP{net.ParseIP("127.0.0.40")},
				EmailAddresses: []string{"mail@example.local", "badmail@example.local"},
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.local",
					},
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "badmail@example.local",
			},
		},
		// NO CONSTRAINT SUCCESS TESTS
		{
			name:    "ok/dns-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
			},
			want: true,
		},
		{
			name:    "ok/ipv4-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
			},
			want: true,
		},
		{
			name:    "ok/ipv6-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
			},
			want: true,
		},
		{
			name:    "ok/mail-no-constraints",
			options: []NamePolicyOption{},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@smallstep.com"},
			},
			want: true,
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
			want: true,
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
			want: true,
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
			want: true,
		},
		{
			name: "ok/subject-permitted-match",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedCommonNames("this name is allowed"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "this name is allowed",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-excluded-match",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedCommonNames("this name is not allowed"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "some other name",
				},
			},
			want: true,
		},
		// SINGLE SAN TYPE PERMITTED SUCCESS TESTS
		{
			name: "ok/dns-permitted",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want: true,
		},
		{
			name: "ok/dns-permitted-wildcard",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local", "*.x509local"),
				WithAllowLiteralWildcardNames(),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"host.local",
					"test.x509local",
				},
			},
			want: true,
		},
		{
			name: "ok/dns-permitted-wildcard-literal",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local", "*.x509local"),
				WithAllowLiteralWildcardNames(),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"*.local",
					"*.x509local",
				},
			},
			want: true,
		},
		{
			name: "ok/dns-permitted-combined",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local", "*.x509local", "host.example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"example.local",
					"example.x509local",
					"host.example.com",
				},
			},
			want: true,
		},
		{
			name: "ok/dns-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.例.jp"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{
					"JP納豆.例.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
				},
			},
			want: true,
		},
		{
			name: "ok/ipv4-permitted",
			options: []NamePolicyOption{
				WithPermittedCIDRs("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.20")},
			},
			want: true,
		},
		{
			name: "ok/ipv6-permitted",
			options: []NamePolicyOption{
				WithPermittedCIDRs("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7339")},
			},
			want: true,
		},
		{
			name: "ok/mail-permitted-wildcard",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@example.com",
				},
			},
			want: true,
		},
		{
			name: "ok/mail-permitted-plain-domain",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("example.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@example.com",
				},
			},
			want: true,
		},
		{
			name: "ok/mail-permitted-specific-mailbox",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("test@local.com"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@local.com",
				},
			},
			want: true,
		},
		{
			name: "ok/mail-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@例.jp"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{},
			},
			want: true,
		},
		{
			name: "ok/uri-permitted-domain-wildcard",
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "example.local",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/uri-permitted-specific-uri",
			options: []NamePolicyOption{
				WithPermittedURIDomains("test.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "test.local",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/uri-permitted-with-port",
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com:8080",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedURIDomains("*.bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "abc.xn--bcher-kva.example.com",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/uri-permitted-idna-internationalized-domain",
			options: []NamePolicyOption{
				WithPermittedURIDomains("bücher.example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "xn--bcher-kva.example.com",
					},
				},
			},
			want: true,
		},
		// SINGLE SAN TYPE EXCLUDED SUCCESS TESTS
		{
			name: "ok/dns-excluded",
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.notlocal"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"example.local"},
			},
			want: true,
		},
		{
			name: "ok/ipv4-excluded",
			options: []NamePolicyOption{
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("10.10.10.10")},
			},
			want: true,
		},
		{
			name: "ok/ipv6-excluded",
			options: []NamePolicyOption{
				WithExcludedCIDRs("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2003:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want: true,
		},
		{
			name: "ok/mail-excluded",
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@notlocal"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@local"},
			},
			want: true,
		},
		{
			name: "ok/mail-excluded-with-subdomain",
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want: true,
		},
		{
			name: "ok/uri-excluded",
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.google.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: true,
		},
		// SUBJECT SUCCESS TESTS
		{
			name: "ok/subject-empty",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames: []string{"example.local"},
			},
			want: true,
		},
		{
			name: "ok/subject-dns-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-dns-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedDNSDomains("*.notlocal"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "example.local",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-ipv4-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.20",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-ipv4-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("128.0.0.1"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-ipv6-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2001:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-ipv6-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedIPRanges(
					&net.IPNet{
						IP:   net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
						Mask: net.CIDRMask(120, 128),
					},
				),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "2009:0db8:85a3:0000:0000:8a2e:0370:7339",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-email-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedEmailAddresses("@example.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-email-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedEmailAddresses("@example.notlocal"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "mail@example.local",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-uri-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedURIDomains("*.example.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want: true,
		},
		{
			name: "ok/subject-uri-excluded",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedURIDomains("*.smallstep.com"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "https://www.example.com",
				},
			},
			want: true,
		},
		// DIFFERENT SAN TYPE EXCLUDED SUCCESS TESTS
		{
			name: "ok/dns-excluded-with-ip-name", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: true,
		},
		{
			name: "ok/dns-excluded-with-mail", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want: true,
		},
		{
			name: "ok/dns-excluded-with-mail", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/ip-excluded-with-dns", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.local"},
			},
			want: true,
		},
		{
			name: "ok/ip-excluded-with-mail", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.com"},
			},
			want: true,
		},
		{
			name: "ok/ip-excluded-with-mail", // when only IP is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/mail-excluded-with-dns", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.local"},
			},
			want: true,
		},
		{
			name: "ok/mail-excluded-with-ip", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: true,
		},
		{
			name: "ok/mail-excluded-with-uri", // when only mail is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{
						Scheme: "https",
						Host:   "www.example.com",
					},
				},
			},
			want: true,
		},
		{
			name: "ok/uri-excluded-with-dns", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.example.local"),
			},
			cert: &x509.Certificate{
				DNSNames: []string{"test.example.local"},
			},
			want: true,
		},
		{
			name: "ok/uri-excluded-with-dns", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.example.local"),
			},
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: true,
		},
		{
			name: "ok/uri-excluded-with-mail", // when only URI is exluded, we allow anything else
			options: []NamePolicyOption{
				WithExcludedURIDomains("*.example.local"),
			},
			cert: &x509.Certificate{
				EmailAddresses: []string{"mail@example.local"},
			},
			want: true,
		},
		{
			name: "ok/dns-excluded-with-subject-ip-name", // when only DNS is exluded, we allow anything else
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithExcludedDNSDomains("*.local"),
			},
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			},
			want: true,
		},
		// COMBINED SUCCESS TESTS
		{
			name: "ok/combined-simple-permitted",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
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
			want: true,
		},
		{
			name: "ok/combined-simple-permitted-without-subject-verification",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
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
			want: true,
		},
		{
			name: "ok/combined-simple-all",
			options: []NamePolicyOption{
				WithSubjectCommonNameVerification(),
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithPermittedEmailAddresses("@example.local"),
				WithPermittedURIDomains("*.example.local"),
				WithExcludedDNSDomains("badhost.local"),
				WithExcludedCIDRs("127.0.0.128/25"),
				WithExcludedEmailAddresses("badmail@example.local"),
				WithExcludedURIDomains("badwww.example.local"),
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
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := New(tt.options...)
			assert.NoError(t, err)
			assert.NotNil(t, engine)
			gotErr := engine.IsX509CertificateAllowed(tt.cert)
			wantErr := tt.wantErr != nil

			if (gotErr != nil) != wantErr {
				t.Errorf("NamePolicyEngine.IsX509CertificateAllowed() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotErr != nil {
				var npe *NamePolicyError
				assert.True(t, errors.As(gotErr, &npe))
				assert.NotEqual(t, "", npe.Error())
				assert.Equal(t, tt.wantErr.Reason, npe.Reason)
				assert.Equal(t, tt.wantErr.NameType, npe.NameType)
				assert.Equal(t, tt.wantErr.Name, npe.Name)
				assert.NotEqual(t, "", npe.Detail())
				//assert.Equals(t, tt.err.Reason, npe.Reason) // NOTE: reason detail is skipped; it's a detail
			}

			// Perform the same tests for a CSR, which are similar to Certificates
			csr := &x509.CertificateRequest{
				Subject:        tt.cert.Subject,
				DNSNames:       tt.cert.DNSNames,
				EmailAddresses: tt.cert.EmailAddresses,
				IPAddresses:    tt.cert.IPAddresses,
				URIs:           tt.cert.URIs,
			}
			gotErr = engine.IsX509CertificateRequestAllowed(csr)
			wantErr = tt.wantErr != nil
			if (gotErr != nil) != wantErr {
				t.Errorf("NamePolicyEngine.AreCSRNamesAllowed() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotErr != nil {
				var npe *NamePolicyError
				assert.True(t, errors.As(gotErr, &npe))
				assert.NotEqual(t, "", npe.Error())
				assert.Equal(t, tt.wantErr.Reason, npe.Reason)
				assert.Equal(t, tt.wantErr.NameType, npe.NameType)
				assert.Equal(t, tt.wantErr.Name, npe.Name)
				assert.NotEqual(t, "", npe.Detail())
				//assert.Equals(t, tt.err.Reason, npe.Reason) // NOTE: reason detail is skipped; it's a detail
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
		wantErr *NamePolicyError
	}{
		{
			name: "fail/host-with-permitted-dns-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.example.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "host.example.com",
			},
		},
		{
			name: "fail/host-with-excluded-dns-domain",
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "host.local",
			},
		},
		{
			name: "fail/host-with-permitted-cidr",
			options: []NamePolicyOption{
				WithPermittedCIDRs("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"192.168.0.22",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "192.168.0.22",
			},
		},
		{
			name: "fail/host-with-excluded-cidr",
			options: []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"127.0.0.0",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     "127.0.0.0",
			},
		},
		{
			name: "fail/user-with-permitted-email",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@local",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@local",
			},
		},
		{
			name: "fail/user-with-excluded-email",
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@example.com",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "mail@example.com",
			},
		},
		{
			name: "fail/host-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals("localhost"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "host",
			},
		},
		{
			name: "fail/user-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals("user"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"root",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     "root",
			},
		},
		{
			name: "fail/user-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals("user"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     "user",
			},
		},
		{
			name: "fail/user-with-permitted-principal-as-mail",
			options: []NamePolicyOption{
				WithPermittedPrincipals("ops"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"ops@work", // this is (currently) parsed as an email-like principal; not allowed with just "ops" as the permitted principal
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "ops@work",
			},
		},
		{
			name: "fail/host-principal-with-permitted-dns-domain", // when only DNS is permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "user",
			},
		},
		{
			name: "fail/host-principal-with-permitted-ip-range", // when only IPs are permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedCIDRs("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "user",
			},
		},
		{
			name: "fail/user-principal-with-permitted-email", // when only emails are permitted, username principals are not allowed.
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     "user",
			},
		},
		{
			name: "fail/combined-user",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@smallstep.com"),
				WithExcludedEmailAddresses("root@smallstep.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     "someone",
			},
		},
		{
			name: "fail/combined-user-with-excluded-user-principal",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@smallstep.com"),
				WithExcludedPrincipals("root"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"root",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     "root",
			},
		},
		{
			name: "fail/host-with-permitted-user-principals",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@work"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"example.work",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "example.work",
			},
		},
		{
			name: "fail/user-with-permitted-user-principals",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"herman@work",
				},
			},
			want: false,
			wantErr: &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     "herman@work",
			},
		},
		{
			name: "ok/host-with-permitted-dns-domain",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want: true,
		},
		{
			name: "ok/host-with-excluded-dns-domain",
			options: []NamePolicyOption{
				WithExcludedDNSDomains("*.example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"host.local",
				},
			},
			want: true,
		},
		{
			name: "ok/host-with-permitted-ip",
			options: []NamePolicyOption{
				WithPermittedCIDRs("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"127.0.0.33",
				},
			},
			want: true,
		},
		{
			name: "ok/host-with-excluded-ip",
			options: []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"192.168.0.35",
				},
			},
			want: true,
		},
		{
			name: "ok/host-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals("localhost"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"localhost",
				},
			},
			want: true,
		},
		{
			name: "ok/user-with-permitted-email",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@example.com",
				},
			},
			want: true,
		},
		{
			name: "ok/user-with-excluded-email",
			options: []NamePolicyOption{
				WithExcludedEmailAddresses("@example.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"mail@local",
				},
			},
			want: true,
		},
		{
			name: "ok/user-with-permitted-principals",
			options: []NamePolicyOption{
				WithPermittedPrincipals("*"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"user",
				},
			},
			want: true,
		},
		{
			name: "ok/user-with-excluded-principals",
			options: []NamePolicyOption{
				WithExcludedPrincipals("user"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"root",
				},
			},
			want: true,
		},
		{
			name: "ok/combined-user",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@smallstep.com"),
				WithPermittedPrincipals("*"), // without specifying the wildcard, "someone" would not be allowed.
				WithExcludedEmailAddresses("root@smallstep.com"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want: true,
		},
		{
			name: "ok/combined-user-with-excluded-user-principal",
			options: []NamePolicyOption{
				WithPermittedEmailAddresses("@smallstep.com"),
				WithExcludedEmailAddresses("root@smallstep.com"),
				WithExcludedPrincipals("root"), // unlike the previous test, this implicitly allows any other username principal
			},
			cert: &ssh.Certificate{
				CertType: ssh.UserCert,
				ValidPrincipals: []string{
					"someone@smallstep.com",
					"someone",
				},
			},
			want: true,
		},
		{
			name: "ok/combined-host",
			options: []NamePolicyOption{
				WithPermittedDNSDomains("*.local"),
				WithPermittedCIDRs("127.0.0.1/24"),
				WithExcludedDNSDomains("badhost.local"),
				WithExcludedCIDRs("127.0.0.128/25"),
			},
			cert: &ssh.Certificate{
				CertType: ssh.HostCert,
				ValidPrincipals: []string{
					"example.local",
					"127.0.0.31",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := New(tt.options...)
			assert.NoError(t, err)
			gotErr := engine.IsSSHCertificateAllowed(tt.cert)
			wantErr := tt.wantErr != nil
			if (gotErr != nil) != wantErr {
				t.Errorf("NamePolicyEngine.IsSSHCertificateAllowed() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotErr != nil {
				var npe *NamePolicyError
				assert.True(t, errors.As(gotErr, &npe))
				assert.NotEqual(t, "", npe.Error())
				assert.Equal(t, tt.wantErr.Reason, npe.Reason)
				assert.Equal(t, tt.wantErr.NameType, npe.NameType)
				assert.Equal(t, tt.wantErr.Name, npe.Name)
				assert.NotEqual(t, "", npe.Detail())
				//assert.Equals(t, tt.err.Reason, npe.Reason) // NOTE: reason detail is skipped; it's a detail
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
		"fail/user-ip": func(t *testing.T) test {
			r := emptyResult()
			r.wantIps = []net.IP{net.ParseIP("127.0.0.1")}
			return test{
				cert: &ssh.Certificate{
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"127.0.0.1"},
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
				r:       r,
				wantErr: false,
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
				r:       r,
				wantErr: false,
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
				r:       r,
				wantErr: false,
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
				r:       r,
				wantErr: false,
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

func Test_removeDuplicates(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty-slice",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "single-item",
			input: []string{"x"},
			want:  []string{"x"},
		},
		{
			name:  "ok",
			input: []string{"x", "y", "x", "z", "x", "z", "y"},
			want:  []string{"x", "y", "z"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := removeDuplicates(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("removeDuplicates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_removeDuplicateIPNets(t *testing.T) {
	tests := []struct {
		name  string
		input []*net.IPNet
		want  []*net.IPNet
	}{
		{
			name:  "empty-slice",
			input: []*net.IPNet{},
			want:  []*net.IPNet{},
		},
		{
			name: "single-item",
			input: []*net.IPNet{
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
			},
			want: []*net.IPNet{
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
			},
		},
		{
			name: "multiple",
			input: []*net.IPNet{
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
				{
					IP:   net.ParseIP("192.168.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
				{
					IP:   net.ParseIP("10.10.0.0"),
					Mask: net.IPv4Mask(255, 255, 0, 0),
				},
				{
					IP:   net.ParseIP("192.168.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
				{
					IP:   net.ParseIP("192.168.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
			want: []*net.IPNet{
				{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
				{
					IP:   net.ParseIP("192.168.0.1"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				{
					IP:   net.ParseIP("10.10.0.0"),
					Mask: net.IPv4Mask(255, 255, 0, 0),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRet := removeDuplicateIPNets(tt.input); !reflect.DeepEqual(gotRet, tt.want) {
				t.Errorf("removeDuplicateIPNets() = %v, want %v", gotRet, tt.want)
			}
		})
	}
}

func TestNamePolicyError_Error(t *testing.T) {
	type fields struct {
		Reason   NamePolicyReason
		NameType NameType
		Name     string
		detail   string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "dns-not-allowed",
			fields: fields{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
			want: "dns name \"www.example.com\" not allowed",
		},
		{
			name: "dns-cannot-parse-domain",
			fields: fields{
				Reason:   CannotParseDomain,
				NameType: DNSNameType,
				Name:     "www.example.com",
			},
			want: "cannot parse dns domain \"www.example.com\"",
		},
		{
			name: "email-cannot-parse",
			fields: fields{
				Reason:   CannotParseRFC822Name,
				NameType: EmailNameType,
				Name:     "mail@example.com",
			},
			want: "cannot parse email rfc822Name \"mail@example.com\"",
		},
		{
			name: "uri-cannot-match",
			fields: fields{
				Reason:   CannotMatchNameToConstraint,
				NameType: URINameType,
				Name:     "https://*.local",
			},
			want: "error matching uri name \"https://*.local\" to constraint",
		},
		{
			name: "unknown",
			fields: fields{
				Reason:   -1,
				NameType: DNSNameType,
				Name:     "some name",
				detail:   "detail string",
			},
			want: "unknown error reason (-1): detail string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &NamePolicyError{
				Reason:   tt.fields.Reason,
				NameType: tt.fields.NameType,
				Name:     tt.fields.Name,
				detail:   tt.fields.detail,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("NamePolicyError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
