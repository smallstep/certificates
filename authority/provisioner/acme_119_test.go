//go:build !go1.18
// +build !go1.18

package provisioner

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"
)

func TestACME_GetAttestationRoots(t *testing.T) {
	appleCA, err := os.ReadFile("testdata/certs/apple-att-ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	yubicoCA, err := os.ReadFile("testdata/certs/yubico-piv-ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(appleCA)
	pool.AppendCertsFromPEM(yubicoCA)

	type fields struct {
		Type             string
		Name             string
		AttestationRoots []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   *x509.CertPool
		want1  bool
	}{
		{"ok", fields{"ACME", "acme", bytes.Join([][]byte{appleCA, yubicoCA}, []byte("\n"))}, pool, true},
		{"nil", fields{"ACME", "acme", nil}, nil, false},
		{"empty", fields{"ACME", "acme", []byte{}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				Type:             tt.fields.Type,
				Name:             tt.fields.Name,
				AttestationRoots: tt.fields.AttestationRoots,
			}
			if err := p.Init(Config{
				Claims:    globalProvisionerClaims,
				Audiences: testAudiences,
			}); err != nil {
				t.Fatal(err)
			}
			got, got1 := p.GetAttestationRoots()
			if tt.want == nil && got != nil {
				t.Errorf("ACME.GetAttestationRoots() got = %v, want %v", got, tt.want)
			} else if !tt.want.Equal(got) {
				t.Errorf("ACME.GetAttestationRoots() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ACME.GetAttestationRoots() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
