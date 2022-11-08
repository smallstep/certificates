package identity

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/api"
	"go.step.sm/crypto/pemutil"
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
		{"ok", func() { IdentityFile = returnInput("testdata/config/identity.json") }, expected, false},
		{"fail read", func() { IdentityFile = returnInput("testdata/config/missing.json") }, nil, true},
		{"fail unmarshal", func() { IdentityFile = returnInput("testdata/config/fail.json") }, nil, true},
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
		{"tunnelTLS", fields{"tTLS"}, TunnelTLS},
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
		Host        string
		Root        string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok mTLS", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key", "", ""}, false},
		{"ok tTLS", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/root_ca.crt"}, false},
		{"ok disabled", fields{}, false},
		{"fail type", fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key", "", ""}, true},
		{"fail certificate", fields{"mTLS", "", "testdata/identity/identity_key", "", ""}, true},
		{"fail key", fields{"mTLS", "testdata/identity/identity.crt", "", "", ""}, true},
		{"fail key", fields{"tTLS", "testdata/identity/identity.crt", "", "tunnel:443", "testdata/certs/root_ca.crt"}, true},
		{"fail missing certificate", fields{"mTLS", "testdata/identity/missing.crt", "testdata/identity/identity_key", "", ""}, true},
		{"fail missing certificate", fields{"tTLS", "testdata/identity/missing.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/root_ca.crt"}, true},
		{"fail missing key", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key", "", ""}, true},
		{"fail missing key", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key", "tunnel:443", "testdata/certs/root_ca.crt"}, true},
		{"fail host", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key", "", "testdata/certs/root_ca.crt"}, true},
		{"fail root", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/missing.crt"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
				Host:        tt.fields.Host,
				Root:        tt.fields.Root,
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
		{"ok mTLS", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, expected, false},
		{"ok tTLS", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, expected, false},
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

func TestWriteDefaultIdentity(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "go-tests")
	if err != nil {
		t.Fatal(err)
	}

	oldConfigDir := configDir
	oldIdentityDir := identityDir
	oldIdentityFile := IdentityFile
	defer func() {
		configDir = oldConfigDir
		identityDir = oldIdentityDir
		IdentityFile = oldIdentityFile
		os.RemoveAll(tmpDir)
	}()

	certs, err := pemutil.ReadCertificateBundle("testdata/identity/identity.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := pemutil.Read("testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}

	var certChain []api.Certificate
	for _, c := range certs {
		certChain = append(certChain, api.Certificate{Certificate: c})
	}

	configDir = returnInput(filepath.Join(tmpDir, "config"))
	identityDir = returnInput(filepath.Join(tmpDir, "identity"))
	IdentityFile = returnInput(filepath.Join(tmpDir, "config", "identity.json"))

	type args struct {
		certChain []api.Certificate
		key       crypto.PrivateKey
	}
	tests := []struct {
		name    string
		prepare func()
		args    args
		wantErr bool
	}{
		{"ok", func() {}, args{certChain, key}, false},
		{"fail mkdir config", func() {
			configDir = returnInput(filepath.Join(tmpDir, "identity", "identity.crt"))
			identityDir = returnInput(filepath.Join(tmpDir, "identity"))
		}, args{certChain, key}, true},
		{"fail mkdir identity", func() {
			configDir = returnInput(filepath.Join(tmpDir, "config"))
			identityDir = returnInput(filepath.Join(tmpDir, "identity", "identity.crt"))
		}, args{certChain, key}, true},
		{"fail certificate", func() {
			configDir = returnInput(filepath.Join(tmpDir, "config"))
			identityDir = returnInput(filepath.Join(tmpDir, "bad-dir"))
			os.MkdirAll(identityDir(), 0600)
		}, args{certChain, key}, true},
		{"fail key", func() {
			configDir = returnInput(filepath.Join(tmpDir, "config"))
			identityDir = returnInput(filepath.Join(tmpDir, "identity"))
		}, args{certChain, "badKey"}, true},
		{"fail write identity", func() {
			configDir = returnInput(filepath.Join(tmpDir, "bad-dir"))
			identityDir = returnInput(filepath.Join(tmpDir, "identity"))
			IdentityFile = returnInput(filepath.Join(configDir(), "identity.json"))
			os.MkdirAll(configDir(), 0600)
		}, args{certChain, key}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			if err := WriteDefaultIdentity(tt.args.certChain, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("WriteDefaultIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIdentity_GetClientCertificateFunc(t *testing.T) {
	expected, err := tls.LoadX509KeyPair("testdata/identity/identity.crt", "testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		Type        string
		Certificate string
		Key         string
		Host        string
		Root        string
	}
	tests := []struct {
		name    string
		fields  fields
		want    *tls.Certificate
		wantErr bool
	}{
		{"ok mTLS", fields{"mtls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "", ""}, &expected, false},
		{"ok tTLS", fields{"ttls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/root_ca.crt"}, &expected, false},
		{"fail missing cert", fields{"mTLS", "testdata/identity/missing.crt", "testdata/identity/identity_key", "", ""}, nil, true},
		{"fail missing key", fields{"tTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key", "tunnel:443", "testdata/certs/root_ca.crt"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
				Host:        tt.fields.Host,
				Root:        tt.fields.Root,
			}
			fn := i.GetClientCertificateFunc()
			got, err := fn(&tls.CertificateRequestInfo{})
			if (err != nil) != tt.wantErr {
				t.Errorf("Identity.GetClientCertificateFunc() = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Identity.GetClientCertificateFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_GetCertPool(t *testing.T) {
	type fields struct {
		Type        string
		Certificate string
		Key         string
		Host        string
		Root        string
	}
	tests := []struct {
		name         string
		fields       fields
		wantSubjects [][]byte
		wantErr      bool
	}{
		{"ok", fields{"ttls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/root_ca.crt"}, [][]byte{[]byte("0\x1c1\x1a0\x18\x06\x03U\x04\x03\x13\x11Smallstep Root CA")}, false},
		{"ok nil", fields{"ttls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", ""}, nil, false},
		{"fail missing", fields{"ttls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/certs/missing.crt"}, nil, true},
		{"fail no cert", fields{"ttls", "testdata/identity/identity.crt", "testdata/identity/identity_key", "tunnel:443", "testdata/secrets/root_ca_key"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
				Host:        tt.fields.Host,
				Root:        tt.fields.Root,
			}
			got, err := i.GetCertPool()
			if (err != nil) != tt.wantErr {
				t.Errorf("Identity.GetCertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				//nolint:staticcheck // we don't have a different way to check
				// the certificates in the pool.
				subjects := got.Subjects()
				if !reflect.DeepEqual(subjects, tt.wantSubjects) {
					t.Errorf("Identity.GetCertPool() = %x, want %x", subjects, tt.wantSubjects)
				}
			}

		})
	}
}

type renewer struct {
	pool *x509.CertPool
	sign *api.SignResponse
	err  error
}

func (r *renewer) GetRootCAs() *x509.CertPool {
	return r.pool
}

func (r *renewer) Renew(tr http.RoundTripper) (*api.SignResponse, error) {
	return r.sign, r.err
}

func TestIdentity_Renew(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "go-tests")
	if err != nil {
		t.Fatal(err)
	}

	oldIdentityDir := identityDir
	identityDir = returnInput("testdata/identity")
	defer func() {
		identityDir = oldIdentityDir
		os.RemoveAll(tmpDir)
	}()

	certs, err := pemutil.ReadCertificateBundle("testdata/identity/identity.crt")
	if err != nil {
		t.Fatal(err)
	}

	ok := &renewer{
		sign: &api.SignResponse{
			ServerPEM: api.Certificate{Certificate: certs[0]},
			CaPEM:     api.Certificate{Certificate: certs[1]},
			CertChainPEM: []api.Certificate{
				{Certificate: certs[0]},
				{Certificate: certs[1]},
			},
		},
	}

	okOld := &renewer{
		sign: &api.SignResponse{
			ServerPEM: api.Certificate{Certificate: certs[0]},
			CaPEM:     api.Certificate{Certificate: certs[1]},
		},
	}

	fail := &renewer{
		err: fmt.Errorf("an error"),
	}

	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	type args struct {
		client Renewer
	}
	tests := []struct {
		name    string
		prepare func()
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, false},
		{"ok old", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{okOld}, false},
		{"ok disabled", func() {}, fields{}, args{nil}, false},
		{"fail type", func() {}, fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, true},
		{"fail renew", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{fail}, true},
		{"fail certificate", func() {}, fields{"mTLS", "testdata/certs/server.crt", "testdata/identity/identity_key"}, args{ok}, true},
		{"fail write identity", func() {
			identityDir = returnInput(filepath.Join(tmpDir, "bad-dir"))
			os.MkdirAll(identityDir(), 0600)
		}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			if err := i.Renew(tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("Identity.Renew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
