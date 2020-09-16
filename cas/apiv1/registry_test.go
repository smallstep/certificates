package apiv1

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestRegister(t *testing.T) {
	t.Cleanup(func() {
		registry = new(sync.Map)
	})
	type args struct {
		t  Type
		fn CertificateAuthorityServiceNewFunc
	}
	tests := []struct {
		name    string
		args    args
		want    CertificateAuthorityService
		wantErr bool
	}{
		{"ok", args{"TestCAS", func(ctx context.Context, opts Options) (CertificateAuthorityService, error) {
			return &testCAS{}, nil
		}}, &testCAS{}, false},
		{"error", args{"ErrorCAS", func(ctx context.Context, opts Options) (CertificateAuthorityService, error) {
			return nil, fmt.Errorf("an error")
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Register(tt.args.t, tt.args.fn)
			fmt.Println(registry)
			fn, ok := registry.Load(tt.args.t.String())
			if !ok {
				t.Errorf("Register() failed")
				return
			}
			got, err := fn.(CertificateAuthorityServiceNewFunc)(context.Background(), Options{})
			if (err != nil) != tt.wantErr {
				t.Errorf("CertificateAuthorityServiceNewFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateAuthorityServiceNewFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadCertificateAuthorityServiceNewFunc(t *testing.T) {
	mockRegister(t)
	type args struct {
		t Type
	}
	tests := []struct {
		name   string
		args   args
		want   CertificateAuthorityService
		wantOk bool
	}{
		{"default", args{""}, &testCAS{name: SoftCAS}, true},
		{"SoftCAS", args{"SoftCAS"}, &testCAS{name: SoftCAS}, true},
		{"CloudCAS", args{"CloudCAS"}, &testCAS{name: CloudCAS}, true},
		{"softcas", args{"softcas"}, &testCAS{name: SoftCAS}, true},
		{"cloudcas", args{"cloudcas"}, &testCAS{name: CloudCAS}, true},
		{"FailCAS", args{"FailCAS"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, ok := LoadCertificateAuthorityServiceNewFunc(tt.args.t)
			if ok != tt.wantOk {
				t.Errorf("LoadCertificateAuthorityServiceNewFunc() ok = %v, want %v", ok, tt.wantOk)
				return
			}
			if ok {
				got, err := fn(context.Background(), Options{})
				if err != nil {
					t.Errorf("CertificateAuthorityServiceNewFunc() error = %v", err)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("CertificateAuthorityServiceNewFunc() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
