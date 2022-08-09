package cas

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"reflect"
	"testing"

	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/softcas"
)

type mockCAS struct{}

func (m *mockCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	panic("not implemented")
}

func (m *mockCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	panic("not implemented")
}

func (m *mockCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	panic("not implemented")
}

func TestNew(t *testing.T) {
	expected := &softcas.SoftCAS{
		CertificateChain: []*x509.Certificate{{Subject: pkix.Name{CommonName: "Test Issuer"}}},
		Signer:           ed25519.PrivateKey{},
	}

	apiv1.Register(apiv1.Type("nockCAS"), func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return nil, fmt.Errorf("an error")
	})

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
			CertificateChain: []*x509.Certificate{{Subject: pkix.Name{CommonName: "Test Issuer"}}},
			Signer:           ed25519.PrivateKey{},
		}}, expected, false},
		{"ok softcas", args{context.Background(), apiv1.Options{
			Type:             "softcas",
			CertificateChain: []*x509.Certificate{{Subject: pkix.Name{CommonName: "Test Issuer"}}},
			Signer:           ed25519.PrivateKey{},
		}}, expected, false},
		{"ok SoftCAS", args{context.Background(), apiv1.Options{
			Type:             "SoftCAS",
			CertificateChain: []*x509.Certificate{{Subject: pkix.Name{CommonName: "Test Issuer"}}},
			Signer:           ed25519.PrivateKey{},
		}}, expected, false},
		{"fail empty", args{context.Background(), apiv1.Options{}}, (*softcas.SoftCAS)(nil), true},
		{"fail type", args{context.Background(), apiv1.Options{Type: "FailCAS"}}, nil, true},
		{"fail load", args{context.Background(), apiv1.Options{Type: "nockCAS"}}, nil, true},
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

func TestNewCreator(t *testing.T) {
	keyManager, err := kms.New(context.Background(), kmsapi.Options{})
	if err != nil {
		t.Fatal(err)
	}

	apiv1.Register(apiv1.Type("nockCAS"), func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return &mockCAS{}, nil
	})

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    CertificateAuthorityCreator
		wantErr bool
	}{
		{"ok empty", args{context.Background(), apiv1.Options{}}, &softcas.SoftCAS{}, false},
		{"ok softcas", args{context.Background(), apiv1.Options{
			Type: "softcas",
		}}, &softcas.SoftCAS{}, false},
		{"ok SoftCAS", args{context.Background(), apiv1.Options{
			Type:       "SoftCAS",
			KeyManager: keyManager,
		}}, &softcas.SoftCAS{KeyManager: keyManager}, false},
		{"fail type", args{context.Background(), apiv1.Options{Type: "FailCAS"}}, nil, true},
		{"fail no creator", args{context.Background(), apiv1.Options{Type: "nockCAS"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCreator(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCreator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCreator() = %v, want %v", got, tt.want)
			}
		})
	}
}
