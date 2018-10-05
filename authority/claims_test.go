package authority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/ca-component/api"
)

func TestCommonNameClaim_Valid(t *testing.T) {
	tests := map[string]struct {
		cnc api.Claim
		crt *x509.CertificateRequest
		err error
	}{
		"empty-common-name": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.CertificateRequest{},
			err: errors.New("common name cannot be empty"),
		},
		"wrong-common-name": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bar"}},
			err: errors.New("common name claim failed - got bar, want foo"),
		},
		"ok": {
			cnc: &commonNameClaim{name: "foo"},
			crt: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "foo"}},
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
		iac api.Claim
		crt *x509.CertificateRequest
		err error
	}{
		"unexpected-ip": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("1.1.1.1")}},
			err: errors.New("IP addresses claim failed - got 1.1.1.1, want 127.0.0.1"),
		},
		"invalid-matcher-nonempty-ips": {
			iac: &ipAddressesClaim{name: "invalid"},
			crt: &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}},
			err: errors.New("IP addresses claim failed - got [127.0.0.1], want none"),
		},
		"ok": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}},
		},
		"ok-empty-ips": {
			iac: &ipAddressesClaim{name: "127.0.0.1"},
			crt: &x509.CertificateRequest{IPAddresses: []net.IP{}},
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
		dnc api.Claim
		crt *x509.CertificateRequest
		err error
	}{
		"wrong-dns-name": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.CertificateRequest{DNSNames: []string{"foo", "bar"}},
			err: errors.New("DNS names claim failed - got bar, want foo"),
		},
		"ok": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.CertificateRequest{DNSNames: []string{"foo"}},
		},
		"ok-empty-dnsNames": {
			dnc: &dnsNamesClaim{"foo"},
			crt: &x509.CertificateRequest{},
		},
		"ok-multiple-identical-dns-entries": {
			dnc: &dnsNamesClaim{name: "foo"},
			crt: &x509.CertificateRequest{DNSNames: []string{"foo", "foo", "foo"}},
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
