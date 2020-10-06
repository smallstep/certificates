package cas

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/cas/softcas"

	"github.com/smallstep/certificates/cas/apiv1"
)

func TestNew(t *testing.T) {
	expected := &softcas.SoftCAS{
		Issuer: &x509.Certificate{Subject: pkix.Name{CommonName: "Test Issuer"}},
		Signer: ed25519.PrivateKey{},
	}
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    CertificateAuthorityService
		wantErr bool
	}{
		{"ok default", args{context.Background(), apiv1.Options{
			Issuer: &x509.Certificate{Subject: pkix.Name{CommonName: "Test Issuer"}},
			Signer: ed25519.PrivateKey{},
		}}, expected, false},
		{"ok softcas", args{context.Background(), apiv1.Options{
			Type:   "softcas",
			Issuer: &x509.Certificate{Subject: pkix.Name{CommonName: "Test Issuer"}},
			Signer: ed25519.PrivateKey{},
		}}, expected, false},
		{"ok SoftCAS", args{context.Background(), apiv1.Options{
			Type:   "SoftCAS",
			Issuer: &x509.Certificate{Subject: pkix.Name{CommonName: "Test Issuer"}},
			Signer: ed25519.PrivateKey{},
		}}, expected, false},
		{"fail empty", args{context.Background(), apiv1.Options{}}, (*softcas.SoftCAS)(nil), true},
		{"fail type", args{context.Background(), apiv1.Options{Type: "FailCAS"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %#v, want %v", got, tt.want)
			}
		})
	}
}
