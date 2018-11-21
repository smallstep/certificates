package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
)

func Test_setTLSOptions(t *testing.T) {
	fail := func() TLSOption {
		return func(c *tls.Config) error {
			return fmt.Errorf("an error")
		}
	}
	type args struct {
		c       *tls.Config
		options []TLSOption
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{&tls.Config{}, []TLSOption{RequireAndVerifyClientCert()}}, false},
		{"ok", args{&tls.Config{}, []TLSOption{VerifyClientCertIfGiven()}}, false},
		{"fail", args{&tls.Config{}, []TLSOption{VerifyClientCertIfGiven(), fail()}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := setTLSOptions(tt.args.c, tt.args.options); (err != nil) != tt.wantErr {
				t.Errorf("setTLSOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequireAndVerifyClientCert(t *testing.T) {
	tests := []struct {
		name string
		want *tls.Config
	}{
		{"ok", &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := RequireAndVerifyClientCert()(got); err != nil {
				t.Errorf("RequireAndVerifyClientCert() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RequireAndVerifyClientCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyClientCertIfGiven(t *testing.T) {
	tests := []struct {
		name string
		want *tls.Config
	}{
		{"ok", &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := VerifyClientCertIfGiven()(got); err != nil {
				t.Errorf("VerifyClientCertIfGiven() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VerifyClientCertIfGiven() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddRootCA(t *testing.T) {
	cert := parseCertificate(rootPEM)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *tls.Config
	}{
		{"ok", args{cert}, &tls.Config{RootCAs: pool}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddRootCA(tt.args.cert)(got); err != nil {
				t.Errorf("AddRootCA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddRootCA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddClientCA(t *testing.T) {
	cert := parseCertificate(rootPEM)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *tls.Config
	}{
		{"ok", args{cert}, &tls.Config{ClientCAs: pool}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddClientCA(tt.args.cert)(got); err != nil {
				t.Errorf("AddClientCA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddClientCA() = %v, want %v", got, tt.want)
			}
		})
	}
}
