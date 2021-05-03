package config

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestTLSVersion_Validate(t *testing.T) {
	tests := []struct {
		name    string
		v       TLSVersion
		wantErr bool
	}{
		{"default", TLSVersion(0), false},
		{"1.0", TLSVersion(1.0), false},
		{"1.1", TLSVersion(1.1), false},
		{"1.2", TLSVersion(1.2), false},
		{"1.3", TLSVersion(1.3), false},
		{"0.99", TLSVersion(0.99), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("TLSVersion.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSVersion_String(t *testing.T) {
	tests := []struct {
		name string
		v    TLSVersion
		want string
	}{
		{"default", TLSVersion(0), "1.3"},
		{"1.0", TLSVersion(1.0), "1.0"},
		{"1.1", TLSVersion(1.1), "1.1"},
		{"1.2", TLSVersion(1.2), "1.2"},
		{"1.3", TLSVersion(1.3), "1.3"},
		{"0.99", TLSVersion(0.99), "unexpected value: 0.990000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("TLSVersion.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCipherSuites_Validate(t *testing.T) {
	tests := []struct {
		name    string
		c       CipherSuites
		wantErr bool
	}{
		{"TLS_RSA_WITH_RC4_128_SHA", CipherSuites{"TLS_RSA_WITH_RC4_128_SHA"}, false},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuites{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, false},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_RSA_WITH_AES_128_CBC_SHA"}, false},
		{"TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_RSA_WITH_AES_256_CBC_SHA"}, false},
		{"TLS_RSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_RSA_WITH_AES_128_CBC_SHA256"}, false},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_RSA_WITH_AES_128_GCM_SHA256"}, false},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_RSA_WITH_AES_256_GCM_SHA384"}, false},
		{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"}, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"}, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"}, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"}, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}, false},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"}, false},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"}, false},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}, false},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, false},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}, false},
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}, false},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, false},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", CipherSuites{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"}, false},
		{"multiple", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, false},
		{"fail", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_BAD_CIPHERSUITE"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CipherSuites.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCipherSuites_Value(t *testing.T) {
	tests := []struct {
		name string
		c    CipherSuites
		want []uint16
	}{
		{"TLS_RSA_WITH_RC4_128_SHA", CipherSuites{"TLS_RSA_WITH_RC4_128_SHA"}, []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuites{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_RSA_WITH_AES_128_CBC_SHA"}, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}},
		{"TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_RSA_WITH_AES_256_CBC_SHA"}, []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}},
		{"TLS_RSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_RSA_WITH_AES_128_CBC_SHA256"}, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA256}},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_RSA_WITH_AES_128_GCM_SHA256"}, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_RSA_WITH_AES_256_GCM_SHA384"}, []uint16{tls.TLS_RSA_WITH_AES_256_GCM_SHA384}},
		{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305}},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"}, []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}},
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuites{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", CipherSuites{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"}, []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}},
		{"multiple", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"fail", CipherSuites{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_BAD_CIPHERSUITE"}, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Value(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CipherSuites.Value() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSOptions_TLSConfig(t *testing.T) {
	type fields struct {
		CipherSuites  CipherSuites
		MinVersion    TLSVersion
		MaxVersion    TLSVersion
		Renegotiation bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *tls.Config
	}{
		{"default", fields{DefaultTLSCipherSuites, DefaultTLSMinVersion, DefaultTLSMaxVersion, DefaultTLSRenegotiation}, &tls.Config{
			CipherSuites:  []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			MinVersion:    tls.VersionTLS12,
			MaxVersion:    tls.VersionTLS13,
			Renegotiation: tls.RenegotiateNever,
		}},
		{"renegotation", fields{DefaultTLSCipherSuites, DefaultTLSMinVersion, DefaultTLSMaxVersion, true}, &tls.Config{
			CipherSuites:  []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			MinVersion:    tls.VersionTLS12,
			MaxVersion:    tls.VersionTLS13,
			Renegotiation: tls.RenegotiateFreelyAsClient,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &TLSOptions{
				CipherSuites:  tt.fields.CipherSuites,
				MinVersion:    tt.fields.MinVersion,
				MaxVersion:    tt.fields.MaxVersion,
				Renegotiation: tt.fields.Renegotiation,
			}
			if got := o.TLSConfig(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TLSOptions.TLSConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
