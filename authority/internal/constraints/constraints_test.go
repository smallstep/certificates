package constraints

import (
	"crypto/x509"
	"net"
	"net/url"
	"reflect"
	"testing"

	"go.step.sm/crypto/minica"
)

func TestNew(t *testing.T) {
	ca1, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}

	ca2, err := minica.New(
		minica.WithIntermediateTemplate(`{
			"subject": {{ toJson .Subject }},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"nameConstraints": {
				"critical": true,
				"permittedDNSDomains": ["internal.example.org"],
				"excludedDNSDomains": ["internal.example.com"],
				"permittedIPRanges": ["192.168.1.0/24", "192.168.2.1/32"],
				"excludedIPRanges": ["192.168.3.0/24", "192.168.4.0/28"],
				"permittedEmailAddresses": ["root@example.org", "example.org", ".acme.org"],
				"excludedEmailAddresses": ["root@example.com", "example.com", ".acme.com"],
				"permittedURIDomains": ["host.example.org", ".acme.org"],
				"excludedURIDomains": ["host.example.com", ".acme.com"]
			}
		}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		chain []*x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *Engine
	}{
		{"ok", args{[]*x509.Certificate{ca1.Intermediate, ca1.Root}}, &Engine{
			hasNameConstraints: false,
		}},
		{"ok with constraints", args{[]*x509.Certificate{ca2.Intermediate, ca2.Root}}, &Engine{
			hasNameConstraints:  true,
			permittedDNSDomains: []string{"internal.example.org"},
			excludedDNSDomains:  []string{"internal.example.com"},
			permittedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.2.1").To4(), Mask: net.IPMask{255, 255, 255, 255}},
			},
			excludedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.3.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.4.0").To4(), Mask: net.IPMask{255, 255, 255, 240}},
			},
			permittedEmailAddresses: []string{"root@example.org", "example.org", ".acme.org"},
			excludedEmailAddresses:  []string{"root@example.com", "example.com", ".acme.com"},
			permittedURIDomains:     []string{"host.example.org", ".acme.org"},
			excludedURIDomains:      []string{"host.example.com", ".acme.com"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.chain...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_service_Validate(t *testing.T) {

	type fields struct {
		hasNameConstraints      bool
		permittedDNSDomains     []string
		excludedDNSDomains      []string
		permittedIPRanges       []*net.IPNet
		excludedIPRanges        []*net.IPNet
		permittedEmailAddresses []string
		excludedEmailAddresses  []string
		permittedURIDomains     []string
		excludedURIDomains      []string
	}
	type args struct {
		dnsNames       []string
		ipAddresses    []net.IP
		emailAddresses []string
		uris           []*url.URL
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{hasNameConstraints: false}, args{
			dnsNames:       []string{"example.com", "host.example.com"},
			ipAddresses:    []net.IP{{192, 168, 1, 1}, {0x26, 0x00, 0x1f, 0x1c, 0x47, 0x1, 0x9d, 0x00, 0xc3, 0xa7, 0x66, 0x94, 0x87, 0x0f, 0x20, 0x72}},
			emailAddresses: []string{"root@example.com"},
			uris:           []*url.URL{{Scheme: "https", Host: "example.com", Path: "/uuid/c6d1a755-0c12-431e-9136-b64cb3173ec7"}},
		}, false},
		{"ok permitted dns ", fields{
			hasNameConstraints:  true,
			permittedDNSDomains: []string{"example.com"},
		}, args{dnsNames: []string{"example.com", "www.example.com"}}, false},
		{"ok not excluded dns", fields{
			hasNameConstraints: true,
			excludedDNSDomains: []string{"example.org"},
		}, args{dnsNames: []string{"example.com", "www.example.com"}}, false},
		{"ok permitted ip", fields{
			hasNameConstraints: true,
			permittedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.2.1").To4(), Mask: net.IPMask{255, 255, 255, 255}},
			},
		}, args{ipAddresses: []net.IP{{192, 168, 1, 10}, {192, 168, 2, 1}}}, false},
		{"ok not excluded ip", fields{
			hasNameConstraints: true,
			excludedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.2.1").To4(), Mask: net.IPMask{255, 255, 255, 255}},
			},
		}, args{ipAddresses: []net.IP{{192, 168, 2, 2}, {192, 168, 3, 1}}}, false},
		{"ok permitted emails ", fields{
			hasNameConstraints:      true,
			permittedEmailAddresses: []string{"root@example.com", "acme.org", ".acme.com"},
		}, args{emailAddresses: []string{"root@example.com", "name@acme.org", "name@coyote.acme.com", `"(quoted)"@www.acme.com`}}, false},
		{"ok not excluded emails", fields{
			hasNameConstraints:     true,
			excludedEmailAddresses: []string{"root@example.com", "acme.org", ".acme.com"},
		}, args{emailAddresses: []string{"name@example.com", "root@acme.com", "root@other.com"}}, false},
		{"ok permitted uris ", fields{
			hasNameConstraints:  true,
			permittedURIDomains: []string{"example.com", ".acme.com"},
		}, args{uris: []*url.URL{{Scheme: "https", Host: "example.com", Path: "/path"}, {Scheme: "https", Host: "www.acme.com", Path: "/path"}}}, false},
		{"ok not excluded uris", fields{
			hasNameConstraints: true,
			excludedURIDomains: []string{"example.com", ".acme.com"},
		}, args{uris: []*url.URL{{Scheme: "https", Host: "example.org", Path: "/path"}, {Scheme: "https", Host: "acme.com", Path: "/path"}}}, false},
		{"fail permitted dns ", fields{
			hasNameConstraints:  true,
			permittedDNSDomains: []string{"example.com"},
		}, args{dnsNames: []string{"www.example.com", "www.example.org"}}, true},
		{"fail not excluded dns", fields{
			hasNameConstraints: true,
			excludedDNSDomains: []string{"example.org"},
		}, args{dnsNames: []string{"example.com", "www.example.org"}}, true},
		{"fail permitted ip", fields{
			hasNameConstraints: true,
			permittedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.2.1").To4(), Mask: net.IPMask{255, 255, 255, 255}},
			},
		}, args{ipAddresses: []net.IP{{192, 168, 1, 10}, {192, 168, 2, 10}}}, true},
		{"fail not excluded ip", fields{
			hasNameConstraints: true,
			excludedIPRanges: []*net.IPNet{
				{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.IPMask{255, 255, 255, 0}},
				{IP: net.ParseIP("192.168.2.1").To4(), Mask: net.IPMask{255, 255, 255, 255}},
			},
		}, args{ipAddresses: []net.IP{{192, 168, 2, 2}, {192, 168, 1, 1}}}, true},
		{"fail permitted emails ", fields{
			hasNameConstraints:      true,
			permittedEmailAddresses: []string{"root@example.com", "acme.org", ".acme.com"},
		}, args{emailAddresses: []string{"root@example.com", "name@acme.org", "name@acme.com"}}, true},
		{"fail not excluded emails", fields{
			hasNameConstraints:     true,
			excludedEmailAddresses: []string{"root@example.com", "acme.org", ".acme.com"},
		}, args{emailAddresses: []string{"name@example.com", "root@example.com"}}, true},
		{"fail permitted uris ", fields{
			hasNameConstraints:  true,
			permittedURIDomains: []string{"example.com", ".acme.com"},
		}, args{uris: []*url.URL{{Scheme: "https", Host: "example.com", Path: "/path"}, {Scheme: "https", Host: "acme.com", Path: "/path"}}}, true},
		{"fail not excluded uris", fields{
			hasNameConstraints: true,
			excludedURIDomains: []string{"example.com", ".acme.com"},
		}, args{uris: []*url.URL{{Scheme: "https", Host: "www.example.com", Path: "/path"}, {Scheme: "https", Host: "acme.com", Path: "/path"}}}, true},
		{"fail parse emails ", fields{
			hasNameConstraints:      true,
			permittedEmailAddresses: []string{"example.com"},
		}, args{emailAddresses: []string{`(notquoted)@example.com`}}, true},
		{"fail match dns", fields{
			hasNameConstraints:  true,
			permittedDNSDomains: []string{"example.com"},
		}, args{dnsNames: []string{`www.example.com.`}}, true},
		{"fail match email", fields{
			hasNameConstraints:     true,
			excludedEmailAddresses: []string{`(notquoted)@example.com`},
		}, args{emailAddresses: []string{`ok@example.com`}}, true},
		{"fail match uri", fields{
			hasNameConstraints:  true,
			permittedURIDomains: []string{"example.com"},
		}, args{uris: []*url.URL{{Scheme: "urn", Opaque: "uuid:36efb1ae-6617-4b23-b799-874a37aaea1c"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Engine{
				hasNameConstraints:      tt.fields.hasNameConstraints,
				permittedDNSDomains:     tt.fields.permittedDNSDomains,
				excludedDNSDomains:      tt.fields.excludedDNSDomains,
				permittedIPRanges:       tt.fields.permittedIPRanges,
				excludedIPRanges:        tt.fields.excludedIPRanges,
				permittedEmailAddresses: tt.fields.permittedEmailAddresses,
				excludedEmailAddresses:  tt.fields.excludedEmailAddresses,
				permittedURIDomains:     tt.fields.permittedURIDomains,
				excludedURIDomains:      tt.fields.excludedURIDomains,
			}
			if err := s.Validate(tt.args.dnsNames, tt.args.ipAddresses, tt.args.emailAddresses, tt.args.uris); (err != nil) != tt.wantErr {
				t.Errorf("service.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
