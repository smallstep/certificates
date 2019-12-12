package identity

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestLoadDefaultIdentity(t *testing.T) {
	oldFile := IdentityFile
	defer func() {
		IdentityFile = oldFile
	}()

	expected := &Identity{
		Type:        "mTLS",
		Certificate: "testdata/identity/identity.crt",
		Key:         "testdata/identity/identity_key",
	}
	tests := []struct {
		name    string
		prepare func()
		want    *Identity
		wantErr bool
	}{
		{"ok", func() { IdentityFile = "testdata/config/identity.json" }, expected, false},
		{"fail read", func() { IdentityFile = "testdata/config/missing.json" }, nil, true},
		{"fail unmarshal", func() { IdentityFile = "testdata/config/fail.json" }, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			got, err := LoadDefaultIdentity()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadDefaultIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadDefaultIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_Kind(t *testing.T) {
	type fields struct {
		Type string
	}
	tests := []struct {
		name   string
		fields fields
		want   Type
	}{
		{"disabled", fields{""}, Disabled},
		{"mutualTLS", fields{"mTLS"}, MutualTLS},
		{"unknown", fields{"unknown"}, Type("unknown")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type: tt.fields.Type,
			}
			if got := i.Kind(); got != tt.want {
				t.Errorf("Identity.Kind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_Validate(t *testing.T) {
	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, false},
		{"ok disabled", fields{}, false},
		{"fail type", fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, true},
		{"fail certificate", fields{"mTLS", "", "testdata/identity/identity_key"}, true},
		{"fail key", fields{"mTLS", "testdata/identity/identity.crt", ""}, true},
		{"fail missing certificate", fields{"mTLS", "testdata/identity/missing.crt", "testdata/identity/identity_key"}, true},
		{"fail missing key", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			if err := i.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Identity.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIdentity_TLSCertificate(t *testing.T) {
	expected, err := tls.LoadX509KeyPair("testdata/identity/identity.crt", "testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	tests := []struct {
		name    string
		fields  fields
		want    tls.Certificate
		wantErr bool
	}{
		{"ok", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, expected, false},
		{"ok disabled", fields{}, tls.Certificate{}, false},
		{"fail type", fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail certificate", fields{"mTLS", "testdata/certs/server.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail not after", fields{"mTLS", "testdata/identity/expired.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail not before", fields{"mTLS", "testdata/identity/not_before.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			got, err := i.TLSCertificate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Identity.TLSCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Identity.TLSCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fileExists(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{"testdata/identity/identity.crt"}, false},
		{"missing", args{"testdata/identity/missing.crt"}, true},
		{"directory", args{"testdata/identity"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := fileExists(tt.args.filename); (err != nil) != tt.wantErr {
				t.Errorf("fileExists() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
