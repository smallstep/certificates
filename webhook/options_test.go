package webhook

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

func TestNewRequestBody(t *testing.T) {
	t1 := time.Now()
	t2 := t1.Add(time.Hour)

	type test struct {
		options []RequestBodyOption
		want    *RequestBody
		wantErr bool
	}
	tests := map[string]test{
		"Permanent Identifier": {
			options: []RequestBodyOption{WithAttestationData(&AttestationData{PermanentIdentifier: "mydevice123"})},
			want: &RequestBody{
				AttestationData: &AttestationData{
					PermanentIdentifier: "mydevice123",
				},
			},
			wantErr: false,
		},
		"X509 Certificate Request": {
			options: []RequestBodyOption{
				WithX509CertificateRequest(&x509.CertificateRequest{
					PublicKeyAlgorithm: x509.ECDSA,
					Subject:            pkix.Name{CommonName: "foo"},
					Raw:                []byte("csr der"),
				}),
			},
			want: &RequestBody{
				X509CertificateRequest: &X509CertificateRequest{
					CertificateRequest: &x509util.CertificateRequest{
						PublicKeyAlgorithm: x509.ECDSA,
						Subject:            x509util.Subject{CommonName: "foo"},
					},
					PublicKeyAlgorithm: "ECDSA",
					Raw:                []byte("csr der"),
				},
			},
			wantErr: false,
		},
		"X509 Certificate": {
			options: []RequestBodyOption{
				WithX509Certificate(&x509util.Certificate{}, &x509.Certificate{
					NotBefore:          t1,
					NotAfter:           t2,
					PublicKeyAlgorithm: x509.ECDSA,
				}),
			},
			want: &RequestBody{
				X509Certificate: &X509Certificate{
					Certificate:        &x509util.Certificate{},
					PublicKeyAlgorithm: "ECDSA",
					NotBefore:          t1,
					NotAfter:           t2,
				},
			},
		},
		"SSH Certificate Request": {
			options: []RequestBodyOption{
				WithSSHCertificateRequest(sshutil.CertificateRequest{
					Type:       "User",
					KeyID:      "key1",
					Principals: []string{"areed", "other"},
				})},
			want: &RequestBody{
				SSHCertificateRequest: &SSHCertificateRequest{
					Type:       "User",
					KeyID:      "key1",
					Principals: []string{"areed", "other"},
				},
			},
			wantErr: false,
		},
		"SSH Certificate": {
			options: []RequestBodyOption{
				WithSSHCertificate(
					&sshutil.Certificate{},
					&ssh.Certificate{
						ValidAfter:  uint64(t1.Unix()),
						ValidBefore: uint64(t2.Unix()),
					},
				),
			},
			want: &RequestBody{
				SSHCertificate: &SSHCertificate{
					Certificate: &sshutil.Certificate{},
					ValidAfter:  uint64(t1.Unix()),
					ValidBefore: uint64(t2.Unix()),
				},
			},
			wantErr: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewRequestBody(test.options...)
			if (err != nil) != test.wantErr {
				t.Fatalf("Got err %v, wanted %t", err, test.wantErr)
			}
			assert.Equals(t, test.want, got)
		})
	}
}
