package x509util

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"reflect"
	"testing"
)

func Test_newCertificateRequest(t *testing.T) {

	type args struct {
		cr *x509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want *CertificateRequest
	}{
		{"ok", args{&x509.CertificateRequest{}}, &CertificateRequest{}},
		{"complex", args{&x509.CertificateRequest{
			Extensions: []pkix.Extension{{Id: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
			Subject:    pkix.Name{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:   []string{"foo"},
			PublicKey:  []byte("publicKey"),
		}}, &CertificateRequest{
			Extensions: []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
			Subject:    Subject{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:   []string{"foo"},
			PublicKey:  []byte("publicKey"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newCertificateRequest(tt.args.cr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetCertificate(t *testing.T) {
	type fields struct {
		Version            int
		Subject            Subject
		DNSNames           MultiString
		EmailAddresses     MultiString
		IPAddresses        MultiIP
		URIs               MultiURL
		Extensions         []Extension
		PublicKey          interface{}
		PublicKeyAlgorithm x509.PublicKeyAlgorithm
		Signature          []byte
		SignatureAlgorithm x509.SignatureAlgorithm
	}
	tests := []struct {
		name   string
		fields fields
		want   *Certificate
	}{
		{"ok",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				Signature:          []byte("signature"),
				SignatureAlgorithm: x509.PureEd25519,
			},
			&Certificate{
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertificateRequest{
				Version:            tt.fields.Version,
				Subject:            tt.fields.Subject,
				DNSNames:           tt.fields.DNSNames,
				EmailAddresses:     tt.fields.EmailAddresses,
				IPAddresses:        tt.fields.IPAddresses,
				URIs:               tt.fields.URIs,
				Extensions:         tt.fields.Extensions,
				PublicKey:          tt.fields.PublicKey,
				PublicKeyAlgorithm: tt.fields.PublicKeyAlgorithm,
				Signature:          tt.fields.Signature,
				SignatureAlgorithm: tt.fields.SignatureAlgorithm,
			}
			if got := c.GetCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetLeafCertificate(t *testing.T) {
	type fields struct {
		Version            int
		Subject            Subject
		DNSNames           MultiString
		EmailAddresses     MultiString
		IPAddresses        MultiIP
		URIs               MultiURL
		Extensions         []Extension
		PublicKey          interface{}
		PublicKeyAlgorithm x509.PublicKeyAlgorithm
		Signature          []byte
		SignatureAlgorithm x509.SignatureAlgorithm
	}
	tests := []struct {
		name   string
		fields fields
		want   *Certificate
	}{
		{"ok",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				Signature:          []byte("signature"),
				SignatureAlgorithm: x509.PureEd25519,
			},
			&Certificate{
				Subject:        Subject{CommonName: "foo"},
				DNSNames:       []string{"foo"},
				EmailAddresses: []string{"foo@bar.com"},
				IPAddresses:    []net.IP{net.ParseIP("::1")},
				URIs:           []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:     []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
				ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageClientAuth,
				}),
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
			},
		},
		{"rsa",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          &rsa.PublicKey{},
				PublicKeyAlgorithm: x509.RSA,
				Signature:          []byte("signature"),
				SignatureAlgorithm: x509.SHA256WithRSA,
			},
			&Certificate{
				Subject:        Subject{CommonName: "foo"},
				DNSNames:       []string{"foo"},
				EmailAddresses: []string{"foo@bar.com"},
				IPAddresses:    []net.IP{net.ParseIP("::1")},
				URIs:           []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:     []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
				ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageClientAuth,
				}),
				PublicKey:          &rsa.PublicKey{},
				PublicKeyAlgorithm: x509.RSA,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertificateRequest{
				Version:            tt.fields.Version,
				Subject:            tt.fields.Subject,
				DNSNames:           tt.fields.DNSNames,
				EmailAddresses:     tt.fields.EmailAddresses,
				IPAddresses:        tt.fields.IPAddresses,
				URIs:               tt.fields.URIs,
				Extensions:         tt.fields.Extensions,
				PublicKey:          tt.fields.PublicKey,
				PublicKeyAlgorithm: tt.fields.PublicKeyAlgorithm,
				Signature:          tt.fields.Signature,
				SignatureAlgorithm: tt.fields.SignatureAlgorithm,
			}
			if got := c.GetLeafCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetLeafCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
