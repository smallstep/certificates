package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func Test_setTLSOptions(t *testing.T) {
	fail := func() TLSOption {
		return func(c *Client, tr http.RoundTripper, config *tls.Config) error {
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

	ca := startCATestServer()
	defer ca.Close()
	client, sr, pk := signDuration(ca, "127.0.0.1", 0)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := setTLSOptions(client, sr, pk, tt.args.c, tt.args.options); (err != nil) != tt.wantErr {
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
			if err := RequireAndVerifyClientCert()(nil, nil, got); err != nil {
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
			if err := VerifyClientCertIfGiven()(nil, nil, got); err != nil {
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
			if err := AddRootCA(tt.args.cert)(nil, nil, got); err != nil {
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
			if err := AddClientCA(tt.args.cert)(nil, nil, got); err != nil {
				t.Errorf("AddClientCA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddClientCA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddRootsToRootCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, sr, pk := signDuration(ca, "127.0.0.1", 0)
	tr, err := getTLSOptionsTransport(sr, pk)
	if err != nil {
		t.Fatal(err)
	}

	root, err := ioutil.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert := parseCertificate(string(root))
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tests := []struct {
		name    string
		tr      http.RoundTripper
		want    *tls.Config
		wantErr bool
	}{
		{"ok", tr, &tls.Config{RootCAs: pool}, false},
		{"fail", http.DefaultTransport, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddRootsToRootCAs()(client, tt.tr, got); (err != nil) != tt.wantErr {
				t.Errorf("AddRootsToRootCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddRootsToRootCAs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddRootsToClientCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, sr, pk := signDuration(ca, "127.0.0.1", 0)
	tr, err := getTLSOptionsTransport(sr, pk)
	if err != nil {
		t.Fatal(err)
	}

	root, err := ioutil.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert := parseCertificate(string(root))
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tests := []struct {
		name    string
		tr      http.RoundTripper
		want    *tls.Config
		wantErr bool
	}{
		{"ok", tr, &tls.Config{ClientCAs: pool}, false},
		{"fail", http.DefaultTransport, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddRootsToClientCAs()(client, tt.tr, got); (err != nil) != tt.wantErr {
				t.Errorf("AddRootsToClientCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddRootsToClientCAs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddFederationToRootCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, sr, pk := signDuration(ca, "127.0.0.1", 0)
	tr, err := getTLSOptionsTransport(sr, pk)
	if err != nil {
		t.Fatal(err)
	}

	root, err := ioutil.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	federated, err := ioutil.ReadFile("testdata/secrets/federated_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	crt1 := parseCertificate(string(root))
	crt2 := parseCertificate(string(federated))
	pool := x509.NewCertPool()
	pool.AddCert(crt1)
	pool.AddCert(crt2)

	tests := []struct {
		name    string
		tr      http.RoundTripper
		want    *tls.Config
		wantErr bool
	}{
		{"ok", tr, &tls.Config{RootCAs: pool}, false},
		{"fail", http.DefaultTransport, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddFederationToRootCAs()(client, tt.tr, got); (err != nil) != tt.wantErr {
				t.Errorf("AddFederationToRootCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddFederationToRootCAs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddFederationToClientCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, sr, pk := signDuration(ca, "127.0.0.1", 0)
	tr, err := getTLSOptionsTransport(sr, pk)
	if err != nil {
		t.Fatal(err)
	}

	root, err := ioutil.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	federated, err := ioutil.ReadFile("testdata/secrets/federated_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	crt1 := parseCertificate(string(root))
	crt2 := parseCertificate(string(federated))
	pool := x509.NewCertPool()
	pool.AddCert(crt1)
	pool.AddCert(crt2)

	tests := []struct {
		name    string
		tr      http.RoundTripper
		want    *tls.Config
		wantErr bool
	}{
		{"ok", tr, &tls.Config{ClientCAs: pool}, false},
		{"fail", http.DefaultTransport, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &tls.Config{}
			if err := AddFederationToClientCAs()(client, tt.tr, got); (err != nil) != tt.wantErr {
				t.Errorf("AddFederationToClientCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddFederationToClientCAs() = %v, want %v", got, tt.want)
			}
		})
	}
}
