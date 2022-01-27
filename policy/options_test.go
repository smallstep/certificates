package policy

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/smallstep/assert"
)

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
			constraint: ".xn--fsq.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
			want:       ".xn--fsq.jp",
			wantErr:    false,
		},
		{
			name:       "ok/idna-internationalized-domain-name-lookup-transformed",
			constraint: ".例.jp", // Example value from https://www.w3.org/International/articles/idn-and-iri/
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
			constraint: `mail@xn--bla.local`,
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

func TestNew(t *testing.T) {
	type test struct {
		options []NamePolicyOption
		want    *NamePolicyEngine
		wantErr bool
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/with-permitted-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedDNSDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedDNSDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedDNSDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-dns-domains": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedDNSDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-dns-domain": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedDNSDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-dns-domain": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedDNSDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-dns-domain": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedDNSDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-dns-domain": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedDNSDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-cidrs": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-ipsOrCIDRs-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedIPsOrCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-ipsOrCIDRs-ip": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedIPsOrCIDRs([]string{"127.0.0:1"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-ipsOrCIDRs-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedIPsOrCIDRs([]string{"127.0.0.1//24"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-ipsOrCIDRs-ip": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedIPsOrCIDRs([]string{"127.0.0:1"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedCIDR("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedCIDR("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedCIDR("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-cidr": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedCIDR("127.0.0.1//24"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedEmailAddresses([]string{"*.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedEmailAddresses([]string{"*.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedEmailAddresses([]string{"*.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-emails": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedEmailAddresses([]string{"*.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-email": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedEmailAddress("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-email": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedEmailAddress("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-email": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedEmailAddress("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-email": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedEmailAddress("*.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedURIDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedURIDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedURIDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-uris": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedURIDomains([]string{"**.local"}),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-permitted-uri": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithPermittedURIDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-permitted-uri": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddPermittedURIDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/with-excluded-uri": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					WithExcludedURIDomain("**.local"),
				},
				want:    nil,
				wantErr: true,
			}
		},
		"fail/add-excluded-uri": func(t *testing.T) test {
			return test{
				options: []NamePolicyOption{
					AddExcludedURIDomain("**.local"),
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
				WithPermittedDNSDomains([]string{"*.local", "*.example.com"}),
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
		"ok/add-permitted-dns-wildcard-domains": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomains([]string{"*.local"}),
				AddPermittedDNSDomains([]string{"*.example.com", "*.local"}),
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
				WithExcludedDNSDomains([]string{"*.local", "*.example.com"}),
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
		"ok/add-excluded-dns-domains": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedDNSDomains([]string{"*.local"}),
				AddExcludedDNSDomains([]string{"*.local", "*.example.com"}),
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
		"ok/with-permitted-dns-wildcard-domain": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomain("*.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedDNSDomains:               []string{".example.com"},
					numberOfDNSDomainConstraints:      1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-dns-wildcard-domain": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomain("*.example.com"),
				AddPermittedDNSDomain("*.local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedDNSDomains:               []string{".example.com", ".local"},
					numberOfDNSDomainConstraints:      2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-dns-domain": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomain("www.example.com"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedDNSDomains:               []string{"www.example.com"},
					numberOfDNSDomainConstraints:      1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-dns-domain": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedDNSDomain("www.example.com"),
				AddPermittedDNSDomain("host.local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedDNSDomains:               []string{"www.example.com", "host.local"},
					numberOfDNSDomainConstraints:      2,
					totalNumberOfPermittedConstraints: 2,
					totalNumberOfConstraints:          2,
				},
				wantErr: false,
			}
		},
		"ok/with-permitted-ip-ranges": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIPRanges(
					[]*net.IPNet{
						nw1, nw2,
					},
				),
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
		"ok/add-permitted-ip-ranges": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIPRanges(
					[]*net.IPNet{
						nw1,
					},
				),
				AddPermittedIPRanges(
					[]*net.IPNet{
						nw1, nw2,
					},
				),
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
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIPRanges(
					[]*net.IPNet{
						nw1, nw2,
					},
				),
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
		"ok/add-excluded-ip-ranges": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIPRanges(
					[]*net.IPNet{
						nw1,
					},
				),
				AddExcludedIPRanges(
					[]*net.IPNet{
						nw1, nw2,
					},
				),
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
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedCIDRs([]string{"127.0.0.1/24", "192.168.0.1/24"}),
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
		"ok/add-permitted-cidrs": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedCIDRs([]string{"127.0.0.1/24"}),
				AddPermittedCIDRs([]string{"127.0.0.1/24", "192.168.0.1/24"}),
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
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedCIDRs([]string{"127.0.0.1/24", "192.168.0.1/24"}),
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
		"ok/add-excluded-cidrs": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedCIDRs([]string{"127.0.0.1/24"}),
				AddExcludedCIDRs([]string{"127.0.0.1/24", "192.168.0.1/24"}),
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
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.31/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIPsOrCIDRs([]string{"127.0.0.1/24", "192.168.0.31"}),
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
		"ok/with-excluded-ipsOrCIDRs-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.31/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIPsOrCIDRs([]string{"127.0.0.1/24", "192.168.0.31"}),
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
		"ok/with-permitted-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedCIDR("127.0.0.1/24"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:        1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedCIDR("127.0.0.1/24"),
				AddPermittedCIDR("192.168.0.1/24"),
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
		"ok/with-excluded-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:       1,
					totalNumberOfExcludedConstraints: 1,
					totalNumberOfConstraints:         1,
				},
				wantErr: false,
			}
		},
		"ok/add-excluded-cidr": func(t *testing.T) test {
			_, nw1, err := net.ParseCIDR("127.0.0.1/24")
			assert.FatalError(t, err)
			_, nw2, err := net.ParseCIDR("192.168.0.1/24")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedCIDR("127.0.0.1/24"),
				AddExcludedCIDR("192.168.0.1/24"),
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
		"ok/with-permitted-ipv4": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.15/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIP(ip1),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:        1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-ipv4": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.45/32")
			assert.FatalError(t, err)
			ip2, nw2, err := net.ParseCIDR("192.168.0.55/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIP(ip1),
				AddPermittedIP(ip2),
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
		"ok/with-excluded-ipv4": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.15/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIP(ip1),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:       1,
					totalNumberOfExcludedConstraints: 1,
					totalNumberOfConstraints:         1,
				},
				wantErr: false,
			}
		},
		"ok/add-excluded-ipv4": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.45/32")
			assert.FatalError(t, err)
			ip2, nw2, err := net.ParseCIDR("192.168.0.55/32")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIP(ip1),
				AddExcludedIP(ip2),
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
		"ok/with-permitted-ipv6": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIP(ip1),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:        1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-ipv6": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.10/32")
			assert.FatalError(t, err)
			ip2, nw2, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithPermittedIP(ip1),
				AddPermittedIP(ip2),
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
		"ok/with-excluded-ipv6": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIP(ip1),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedIPRanges: []*net.IPNet{
						nw1,
					},
					numberOfIPRangeConstraints:       1,
					totalNumberOfExcludedConstraints: 1,
					totalNumberOfConstraints:         1,
				},
				wantErr: false,
			}
		},
		"ok/add-excluded-ipv6": func(t *testing.T) test {
			ip1, nw1, err := net.ParseCIDR("127.0.0.10/32")
			assert.FatalError(t, err)
			ip2, nw2, err := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128")
			assert.FatalError(t, err)
			options := []NamePolicyOption{
				WithExcludedIP(ip1),
				AddExcludedIP(ip2),
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
		"ok/with-permitted-emails": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedEmailAddresses([]string{"mail@local", "@example.com"}),
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
		"ok/add-permitted-emails": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedEmailAddresses([]string{"mail@local"}),
				AddPermittedEmailAddresses([]string{"@example.com", "mail@local"}),
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
				WithExcludedEmailAddresses([]string{"mail@local", "@example.com"}),
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
		"ok/add-excluded-emails": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedEmailAddresses([]string{"mail@local"}),
				AddExcludedEmailAddresses([]string{"@example.com", "mail@local"}),
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
		"ok/with-permitted-email": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedEmailAddress("mail@local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedEmailAddresses:           []string{"mail@local"},
					numberOfEmailAddressConstraints:   1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-email": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedEmailAddress("mail@local"),
				AddPermittedEmailAddress("@example.com"),
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
		"ok/with-excluded-email": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedEmailAddress("mail@local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedEmailAddresses:           []string{"mail@local"},
					numberOfEmailAddressConstraints:  1,
					totalNumberOfExcludedConstraints: 1,
					totalNumberOfConstraints:         1,
				},
				wantErr: false,
			}
		},
		"ok/add-excluded-email": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedEmailAddress("mail@local"),
				AddExcludedEmailAddress("@example.com"),
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
				WithPermittedURIDomains([]string{"host.local", "*.example.com"}),
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
		"ok/add-permitted-uris": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedURIDomains([]string{"host.local"}),
				AddPermittedURIDomains([]string{"*.example.com", "host.local"}),
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
				WithExcludedURIDomains([]string{"host.local", "*.example.com"}),
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
		"ok/add-excluded-uris": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedURIDomains([]string{"host.local"}),
				AddExcludedURIDomains([]string{"*.example.com", "host.local"}),
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
		"ok/with-permitted-uri": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedURIDomain("host.local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					permittedURIDomains:               []string{"host.local"},
					numberOfURIDomainConstraints:      1,
					totalNumberOfPermittedConstraints: 1,
					totalNumberOfConstraints:          1,
				},
				wantErr: false,
			}
		},
		"ok/add-permitted-uri": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithPermittedURIDomain("host.local"),
				AddPermittedURIDomain("*.example.com"),
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
		"ok/with-excluded-uri": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedURIDomain("host.local"),
			}
			return test{
				options: options,
				want: &NamePolicyEngine{
					excludedURIDomains:               []string{"host.local"},
					numberOfURIDomainConstraints:     1,
					totalNumberOfExcludedConstraints: 1,
					totalNumberOfConstraints:         1,
				},
				wantErr: false,
			}
		},
		"ok/add-excluded-uri": func(t *testing.T) test {
			options := []NamePolicyOption{
				WithExcludedURIDomain("host.local"),
				AddExcludedURIDomain("*.example.com"),
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
				WithPermittedPrincipals([]string{"root", "ops"}),
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
				WithExcludedPrincipals([]string{"root", "ops"}),
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
