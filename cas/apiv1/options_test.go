package apiv1

import (
	"context"
	"crypto"
	"crypto/x509"
	"sync"
	"testing"
)

type testCAS struct {
	name string
}

func (t *testCAS) CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error) {
	return nil, nil
}

func (t *testCAS) RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error) {
	return nil, nil
}

func (t *testCAS) RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	return nil, nil
}

func mockRegister(t *testing.T) {
	t.Helper()
	Register(SoftCAS, func(ctx context.Context, opts Options) (CertificateAuthorityService, error) {
		return &testCAS{name: SoftCAS}, nil
	})
	Register(CloudCAS, func(ctx context.Context, opts Options) (CertificateAuthorityService, error) {
		return &testCAS{name: CloudCAS}, nil
	})
	t.Cleanup(func() {
		registry = new(sync.Map)
	})
}

func TestOptions_Validate(t *testing.T) {
	mockRegister(t)
	type fields struct {
		Type                 string
		CredentialsFile      string
		CertificateAuthority string
		Issuer               *x509.Certificate
		Signer               crypto.Signer
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"empty", fields{}, false},
		{"SoftCAS", fields{SoftCAS, "", "", nil, nil}, false},
		{"CloudCAS", fields{CloudCAS, "", "", nil, nil}, false},
		{"softcas", fields{"softcas", "", "", nil, nil}, false},
		{"CLOUDCAS", fields{"CLOUDCAS", "", "", nil, nil}, false},
		{"fail", fields{"FailCAS", "", "", nil, nil}, true},
	}
	t.Run("nil", func(t *testing.T) {
		var o *Options
		if err := o.Validate(); err != nil {
			t.Errorf("Options.Validate() error = %v, wantErr %v", err, false)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				Type:                 tt.fields.Type,
				CredentialsFile:      tt.fields.CredentialsFile,
				CertificateAuthority: tt.fields.CertificateAuthority,
				CertificateChain:     []*x509.Certificate{tt.fields.Issuer},
				Signer:               tt.fields.Signer,
			}
			if err := o.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptions_Is(t *testing.T) {
	mockRegister(t)

	type fields struct {
		Type                 string
		CredentialsFile      string
		CertificateAuthority string
		Issuer               *x509.Certificate
		Signer               crypto.Signer
	}
	type args struct {
		t Type
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"empty", fields{}, args{}, true},
		{"SoftCAS", fields{SoftCAS, "", "", nil, nil}, args{"SoftCAS"}, true},
		{"CloudCAS", fields{CloudCAS, "", "", nil, nil}, args{"CloudCAS"}, true},
		{"softcas", fields{"softcas", "", "", nil, nil}, args{SoftCAS}, true},
		{"CLOUDCAS", fields{"CLOUDCAS", "", "", nil, nil}, args{CloudCAS}, true},
		{"UnknownCAS", fields{"UnknownCAS", "", "", nil, nil}, args{"UnknownCAS"}, true},
		{"fail", fields{CloudCAS, "", "", nil, nil}, args{"SoftCAS"}, false},
		{"fail", fields{SoftCAS, "", "", nil, nil}, args{"CloudCAS"}, false},
	}
	t.Run("nil", func(t *testing.T) {
		var o *Options
		if got := o.Is(SoftCAS); got != true {
			t.Errorf("Options.Is() = %v, want %v", got, true)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				Type:                 tt.fields.Type,
				CredentialsFile:      tt.fields.CredentialsFile,
				CertificateAuthority: tt.fields.CertificateAuthority,
				CertificateChain:     []*x509.Certificate{tt.fields.Issuer},
				Signer:               tt.fields.Signer,
			}
			if got := o.Is(tt.args.t); got != tt.want {
				t.Errorf("Options.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
