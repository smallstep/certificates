package policy

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func Test_normalizeAndValidateCommonName(t *testing.T) {
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
			name:       "fail/wildcard",
			constraint: "*",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "ok",
			constraint: "step",
			want:       "step",
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAndValidateCommonName(tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeAndValidateCommonName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeAndValidateCommonName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_normalizeAndValidateDNSDomainConstraint(t *testing.T) {
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
			name:       "fail/wildcard-partial-label",
			constraint: "*xxxx.local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/wildcard-in-the-middle",
			constraint: "x.*.local",
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
			name:       "fail/idna-internationalized-domain-name-lookup",
			constraint: `\00.local`, // invalid IDNA ASCII character
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
			name:       "ok/idna-internationalized-domain-name-punycode",
			constraint: "*.xn--fsq.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			want:       ".xn--fsq.jp",
			wantErr:    false,
		},
		{
			name:       "ok/idna-internationalized-domain-name-lookup-transformed",
			constraint: "*.例.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			want:       ".xn--fsq.jp",
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAndValidateDNSDomainConstraint(tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeAndValidateDNSDomainConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("normalizeAndValidateDNSDomainConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_normalizeAndValidateEmailConstraint(t *testing.T) {
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
			name:       "fail/asterisk",
			constraint: "*.local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/period",
			constraint: ".local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/@period",
			constraint: "@.local",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/too-many-@s",
			constraint: "@local@example.com",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/parse-mailbox",
			constraint: "mail@example.com" + string(byte(0)),
			want:       "",
			wantErr:    true,
		},
		{
			name:       "fail/idna-internationalized-domain",
			constraint: "mail@xn--bla.local",
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
			name:       "fail/parse-domain",
			constraint: "x..example.com",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "ok/wildcard",
			constraint: "@local",
			want:       "local",
			wantErr:    false,
		},
		{
			name:       "ok/specific-mail",
			constraint: "mail@local",
			want:       "mail@local",
			wantErr:    false,
		},
		// TODO(hs): fix the below; doesn't get past parseRFC2821Mailbox; I think it should be allowed.
		// {
		// 	name:       "ok/idna-internationalized-local",
		// 	constraint: `bücher@local`,
		// 	want:       "bücher@local",
		// 	wantErr:    false,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAndValidateEmailConstraint(tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeAndValidateEmailConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("normalizeAndValidateEmailConstraint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type test struct {
		options []NamePolicyOption
		want    *NamePolicyEngine
		wantErr bool
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/with-permitted-common-name": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedCommonNames("*"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-common-name": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedCommonNames(""),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedDNSDomains("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedDNSDomains("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedCIDRs("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedCIDRs("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-ipsOrCIDRs-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedIPsOrCIDRs("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-ipsOrCIDRs-ip": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedIPsOrCIDRs("127.0.0:1"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-ipsOrCIDRs-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedIPsOrCIDRs("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-ipsOrCIDRs-ip": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedIPsOrCIDRs("127.0.0:1"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedEmailAddresses("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedEmailAddresses("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedURIDomains("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedURIDomains("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"ok/default": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{},
				want:    &NamePolicyEngine{},
				wantErr: false,
			}
		},
		"ok/subject-verification": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithSubjectCommonNameVerification(),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					verifySubjectCommonName: true,
				},
				wantErr: false,
			}
		},
		"ok/literal-wildcards": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithAllowLiteralWildcardNames(),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					allowLiteralWildcardNames: true,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-dns-wildcard-domains": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomains("*.local", "*.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedDNSDomains:               []string{".local", ".example.com"},
					numberOfDNSDomainConstraints:      2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-dns-domains": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedDNSDomains("*.local", "*.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedDNSDomains:               []string{".local", ".example.com"},
					numberOfDNSDomainConstraints:     2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-ip-ranges": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithPermittedIPRanges(nw1, nw2),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1, nw2,
					},
					numberOfIPRangeConstraints:        2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-ip-ranges": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithExcludedIPRanges(nw1, nw2),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1, nw2,
					},
					numberOfIPRangeConstraints:       2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-cidrs": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithPermittedCIDRs("127.0.0.1/24", "192.168.0.1/24"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1, nw2,
					},
					numberOfIPRangeConstraints:        2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-cidrs": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithExcludedCIDRs("127.0.0.1/24", "192.168.0.1/24"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1, nw2,
					},
					numberOfIPRangeConstraints:       2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-ipsOrCIDRs-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.31/32")
			assert.NoError(t, err)
			_, nw3, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithPermittedIPsOrCIDRs("127.0.0.1/24", "192.168.0.31", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1, nw2, nw3,
					},
					numberOfIPRangeConstraints:        3,
					totalNumberOfPermittedConstraints: 3,
					totalNumberOfConstraints:          3,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-ipsOrCIDRs-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.NoError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.31/32")
			assert.NoError(t, err)
			_, nw3, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.NoError(t, err)
			options := []NamePolicyOption{
				WithExcludedIPsOrCIDRs("127.0.0.1/24", "192.168.0.31", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1, nw2, nw3,
					},
					numberOfIPRangeConstraints:       3,
					totalNumberOfExcludedConstraints: 3,
					totalNumberOfConstraints:         3,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-emails": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedEmailAddresses("mail@local", "@example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedEmailAddresses:           []string{"mail@local", "example.com"},
					numberOfEmailAddressConstraints:   2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-emails": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedEmailAddresses("mail@local", "@example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedEmailAddresses:           []string{"mail@local", "example.com"},
					numberOfEmailAddressConstraints:  2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-uris": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedURIDomains("host.local", "*.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedURIDomains:               []string{"host.local", ".example.com"},
					numberOfURIDomainConstraints:      2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-uris": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedURIDomains("host.local", "*.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedURIDomains:               []string{"host.local", ".example.com"},
					numberOfURIDomainConstraints:     2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-principals": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedPrincipals("root", "ops"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedPrincipals:               []string{"root", "ops"},
					numberOfPrincipalConstraints:      2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-excluded-principals": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedPrincipals("root", "ops"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedPrincipals:               []string{"root", "ops"},
					numberOfPrincipalConstraints:     2,
					totalNumberOfExcludedConstraints: 2,
					totalNumberOfConstraints:         2,
				},
				wantErr: false,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			got, err := New(tc.options...)
			if (err != nil) != tc.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !cmp.Equal(tc.want, got, cmp.AllowUnexported(NamePolicyEngine{})) {
				t.Errorf("New() diff =\n %s", cmp.Diff(tc.want, got, cmp.AllowUnexported(NamePolicyEngine{})))
			}
		})
	}
}

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
			name:       "fail/domain-with-port",
			constraint: "host.local:8443",
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
			want:       ".xn--fa-hia.de",
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
