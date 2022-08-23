package identity

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"
)

func returnInput(val string) func() string {
	return func() string {
		return val
	}
}

func TestClient(t *testing.T) {
	oldIdentityFile := IdentityFile
	oldDefaultsFile := DefaultsFile
	defer func() {
		IdentityFile = oldIdentityFile
		DefaultsFile = oldDefaultsFile
	}()

	IdentityFile = returnInput("testdata/config/identity.json")
	DefaultsFile = returnInput("testdata/config/defaults.json")

	client, err := LoadClient()
	if err != nil {
		t.Fatal(err)
	}

	okServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer okServer.Close()

	crt, err := tls.LoadX509KeyPair("testdata/certs/server.crt", "testdata/secrets/server_key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/certs/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)

	okServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{crt},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	okServer.StartTLS()

	badServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer badServer.Close()

	if resp, err := client.Get(okServer.URL); err != nil {
		t.Errorf("client.Get() error = %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("client.Get() = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	}

	if _, err := client.Get(badServer.URL); err == nil {
		t.Errorf("client.Get() error = %v, wantErr true", err)
	}
}

func TestClient_ResolveReference(t *testing.T) {
	type fields struct {
		CaURL *url.URL
	}
	type args struct {
		ref *url.URL
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *url.URL
	}{
		{"ok", fields{&url.URL{Scheme: "https", Host: "localhost"}}, args{&url.URL{Path: "/foo"}}, &url.URL{Scheme: "https", Host: "localhost", Path: "/foo"}},
		{"ok", fields{&url.URL{Scheme: "https", Host: "localhost", Path: "/bar"}}, args{&url.URL{Path: "/foo"}}, &url.URL{Scheme: "https", Host: "localhost", Path: "/foo"}},
		{"ok", fields{&url.URL{Scheme: "https", Host: "localhost"}}, args{&url.URL{Path: "/foo", RawQuery: "foo=bar"}}, &url.URL{Scheme: "https", Host: "localhost", Path: "/foo", RawQuery: "foo=bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				CaURL: tt.fields.CaURL,
			}
			if got := c.ResolveReference(tt.args.ref); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.ResolveReference() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadClient(t *testing.T) {
	oldIdentityFile := IdentityFile
	oldDefaultsFile := DefaultsFile
	defer func() {
		IdentityFile = oldIdentityFile
		DefaultsFile = oldDefaultsFile
	}()

	crt, err := tls.LoadX509KeyPair("testdata/identity/identity.crt", "testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/certs/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{crt},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	expected := &Client{
		CaURL: &url.URL{Scheme: "https", Host: "127.0.0.1"},
		Client: &http.Client{
			Transport: tr,
		},
	}

	tests := []struct {
		name    string
		prepare func()
		want    *Client
		wantErr bool
	}{
		{"ok", func() {
			IdentityFile = returnInput("testdata/config/identity.json")
			DefaultsFile = returnInput("testdata/config/defaults.json")
		}, expected, false},
		{"fail identity", func() {
			IdentityFile = returnInput("testdata/config/missing.json")
			DefaultsFile = returnInput("testdata/config/defaults.json")
		}, nil, true},
		{"fail identity", func() {
			IdentityFile = returnInput("testdata/config/fail.json")
			DefaultsFile = returnInput("testdata/config/defaults.json")
		}, nil, true},
		{"fail defaults", func() {
			IdentityFile = returnInput("testdata/config/identity.json")
			DefaultsFile = returnInput("testdata/config/missing.json")
		}, nil, true},
		{"fail defaults", func() {
			IdentityFile = returnInput("testdata/config/identity.json")
			DefaultsFile = returnInput("testdata/config/fail.json")
		}, nil, true},
		{"fail ca", func() {
			IdentityFile = returnInput("testdata/config/identity.json")
			DefaultsFile = returnInput("testdata/config/badca.json")
		}, nil, true},
		{"fail root", func() {
			IdentityFile = returnInput("testdata/config/identity.json")
			DefaultsFile = returnInput("testdata/config/badroot.json")
		}, nil, true},
		{"fail type", func() {
			IdentityFile = returnInput("testdata/config/badIdentity.json")
			DefaultsFile = returnInput("testdata/config/defaults.json")
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			got, err := LoadClient()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("LoadClient() = %#v, want %#v", got, tt.want)
				}
			} else {
				gotTransport := got.Client.Transport.(*http.Transport)
				wantTransport := tt.want.Client.Transport.(*http.Transport)
				switch {
				case gotTransport.TLSClientConfig.GetClientCertificate == nil:
					t.Error("LoadClient() transport does not define GetClientCertificate")
				case !reflect.DeepEqual(got.CaURL, tt.want.CaURL) || !equalPools(gotTransport.TLSClientConfig.RootCAs, wantTransport.TLSClientConfig.RootCAs):
					t.Errorf("LoadClient() = %#v, want %#v", got, tt.want)
				default:
					crt, err := gotTransport.TLSClientConfig.GetClientCertificate(nil)
					if err != nil {
						t.Errorf("LoadClient() GetClientCertificate error = %v", err)
					} else if !reflect.DeepEqual(*crt, wantTransport.TLSClientConfig.Certificates[0]) {
						t.Errorf("LoadClient() GetClientCertificate crt = %#v, want %#v", *crt, wantTransport.TLSClientConfig.Certificates[0])
					}
				}

			}
		})
	}
}

func Test_defaultsConfig_Validate(t *testing.T) {
	type fields struct {
		CaURL string
		Root  string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"https://127.0.0.1", "root_ca.crt"}, false},
		{"fail ca-url", fields{"", "root_ca.crt"}, true},
		{"fail root", fields{"https://127.0.0.1", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultsConfig{
				CaURL: tt.fields.CaURL,
				Root:  tt.fields.Root,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("defaultsConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:staticcheck,gocritic
func equalPools(a, b *x509.CertPool) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	subjects := a.Subjects()
	sA := make([]string, len(subjects))
	for i := range subjects {
		sA[i] = string(subjects[i])
	}
	subjects = b.Subjects()
	sB := make([]string, len(subjects))
	for i := range subjects {
		sB[i] = string(subjects[i])
	}
	sort.Strings(sA)
	sort.Strings(sB)
	return reflect.DeepEqual(sA, sB)
}
