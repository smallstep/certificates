package authority

import (
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	x509 "github.com/smallstep/cli/pkg/x509"
)

func TestCommonNameClaim_Valid(t *testing.T) {
	tests := map[string]struct {
		cnc certClaim
		crt *x509.Certificate
		err error
	}{
		"empty-common-name": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.Certificate{},
			err: errors.New("common name cannot be empty"),
		},
		"wrong-common-name": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.Certificate{Subject: pkix.Name{CommonName: "bar"}},
			err: errors.New("common name claim failed - got bar, want foo"),
		},
		"ok": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.cnc.Valid(tc.crt)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestIPAddressesClaim_Valid(t *testing.T) {
	tests := map[string]struct {
		iac certClaim
		crt *x509.Certificate
		err error
	}{
		"unexpected-ip": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("1.1.1.1")}},
			err: errors.New("IP addresses claim failed - got 1.1.1.1, want 127.0.0.1"),
		},
		"invalid-matcher-nonempty-ips": {
			iac: &ipAddressesClaim{name: "invalid"},
			crt: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}},
			err: errors.New("IP addresses claim failed - got [127.0.0.1], want none"),
		},
		"ok": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}},
		},
		"ok-empty-ips": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.Certificate{IPAddresses: []net.IP{}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.iac.Valid(tc.crt)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestDNSNamesClaim_Valid(t *testing.T) {
	tests := map[string]struct {
		dnc certClaim
		crt *x509.Certificate
		err error
	}{
		"wrong-dns-name": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.Certificate{DNSNames: []string{"foo", "bar"}},
			err: errors.New("DNS names claim failed - got bar, want foo"),
		},
		"ok": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.Certificate{DNSNames: []string{"foo"}},
		},
		"ok-empty-dnsNames": {
			dnc: &dnsNamesClaim{"foo"},
			crt: &x509.Certificate{},
		},
		"ok-multiple-identical-dns-entries": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.Certificate{DNSNames: []string{"foo", "foo", "foo"}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.dnc.Valid(tc.crt)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
