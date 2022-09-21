package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/smallstep/certificates/api"
)

//nolint:gosec // test tls config
func Test_newTLSOptionCtx(t *testing.T) {
	client, err := NewClient("https://ca.smallstep.com", WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	type args struct {
		c      *Client
		config *tls.Config
		sign   *api.SignResponse
	}
	tests := []struct {
		name string
		args args
		want *TLSOptionCtx
	}{
		{"ok", args{client, &tls.Config{}, &api.SignResponse{}}, &TLSOptionCtx{Client: client, Config: &tls.Config{}, Sign: &api.SignResponse{}, mutableConfig: newMutableTLSConfig()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTLSOptionCtx(tt.args.c, tt.args.config, tt.args.sign); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newTLSOptionCtx() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestTLSOptionCtx_apply(t *testing.T) {
	fail := func() TLSOption {
		return func(ctx *TLSOptionCtx) error {
			return fmt.Errorf("an error")
		}
	}

	type fields struct {
		Config *tls.Config
	}
	type args struct {
		options []TLSOption
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{&tls.Config{}}, args{[]TLSOption{RequireAndVerifyClientCert()}}, false},
		{"ok", fields{&tls.Config{}}, args{[]TLSOption{VerifyClientCertIfGiven()}}, false},
		{"fail", fields{&tls.Config{}}, args{[]TLSOption{VerifyClientCertIfGiven(), fail()}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Config:        tt.fields.Config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply(tt.args.options); (err != nil) != tt.wantErr {
				t.Errorf("TLSOptionCtx.apply() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestRequireAndVerifyClientCert(t *testing.T) {
	tests := []struct {
		name string
		want *tls.Config
	}{
		{"ok", &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Config:        &tls.Config{},
				mutableConfig: newMutableTLSConfig(),
			}
			if err := RequireAndVerifyClientCert()(ctx); err != nil {
				t.Errorf("RequireAndVerifyClientCert() error = %v", err)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) {
				t.Errorf("RequireAndVerifyClientCert() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestVerifyClientCertIfGiven(t *testing.T) {
	tests := []struct {
		name string
		want *tls.Config
	}{
		{"ok", &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Config:        &tls.Config{},
				mutableConfig: newMutableTLSConfig(),
			}
			if err := VerifyClientCertIfGiven()(ctx); err != nil {
				t.Errorf("VerifyClientCertIfGiven() error = %v", err)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) {
				t.Errorf("VerifyClientCertIfGiven() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
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
			ctx := &TLSOptionCtx{
				Config:        &tls.Config{},
				mutableConfig: newMutableTLSConfig(),
			}
			if err := AddRootCA(tt.args.cert)(ctx); err != nil {
				t.Errorf("AddRootCA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) && !equalPools(ctx.Config.RootCAs, tt.want.RootCAs) {
				t.Errorf("AddRootCA() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
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
			ctx := &TLSOptionCtx{
				Config:        &tls.Config{},
				mutableConfig: newMutableTLSConfig(),
			}
			if err := AddClientCA(tt.args.cert)(ctx); err != nil {
				t.Errorf("AddClientCA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) && !equalPools(ctx.Config.ClientCAs, tt.want.ClientCAs) {
				t.Errorf("AddClientCA() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddRootsToRootCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert := parseCertificate(string(root))
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{RootCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddRootsToRootCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddRootsToRootCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !equalPools(ctx.Config.RootCAs, tt.want.RootCAs) {
				t.Errorf("AddRootsToRootCAs() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddRootsToClientCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert := parseCertificate(string(root))
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{ClientCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddRootsToClientCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddRootsToClientCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !equalPools(ctx.Config.ClientCAs, tt.want.ClientCAs) {
				t.Errorf("AddRootsToClientCAs() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddFederationToRootCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	federated, err := os.ReadFile("testdata/secrets/federated_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	crt1 := parseCertificate(string(root))
	crt2 := parseCertificate(string(federated))
	pool := x509.NewCertPool()
	pool.AddCert(crt1)
	pool.AddCert(crt2)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{RootCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddFederationToRootCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddFederationToRootCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) {
				// Federated roots are randomly sorted
				if !equalPools(ctx.Config.RootCAs, tt.want.RootCAs) || ctx.Config.ClientCAs != nil {
					t.Errorf("AddFederationToRootCAs() = %v, want %v", ctx.Config, tt.want)
				}
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddFederationToClientCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	federated, err := os.ReadFile("testdata/secrets/federated_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	crt1 := parseCertificate(string(root))
	crt2 := parseCertificate(string(federated))
	pool := x509.NewCertPool()
	pool.AddCert(crt1)
	pool.AddCert(crt2)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{ClientCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddFederationToClientCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddFederationToClientCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) {
				// Federated roots are randomly sorted
				if !equalPools(ctx.Config.ClientCAs, tt.want.ClientCAs) || ctx.Config.RootCAs != nil {
					t.Errorf("AddFederationToClientCAs() = %v, want %v", ctx.Config, tt.want)
				}
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddRootsToCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert := parseCertificate(string(root))
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{ClientCAs: pool, RootCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddRootsToCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddRootsToCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !equalPools(ctx.Config.RootCAs, tt.want.RootCAs) || !equalPools(ctx.Config.ClientCAs, tt.want.ClientCAs) {
				t.Errorf("AddRootsToCAs() = %v, want %v", ctx.Config, tt.want)
			}
		})
	}
}

//nolint:gosec // test tls config
func TestAddFederationToCAs(t *testing.T) {
	ca := startCATestServer()
	defer ca.Close()

	client, err := NewClient(ca.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	clientFail, err := NewClient(ca.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.ReadFile("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	federated, err := os.ReadFile("testdata/secrets/federated_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	crt1 := parseCertificate(string(root))
	crt2 := parseCertificate(string(federated))
	pool := x509.NewCertPool()
	pool.AddCert(crt1)
	pool.AddCert(crt2)

	type args struct {
		client *Client
		config *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		{"ok", args{client, &tls.Config{}}, &tls.Config{ClientCAs: pool, RootCAs: pool}, false},
		{"fail", args{clientFail, &tls.Config{}}, &tls.Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &TLSOptionCtx{
				Client:        tt.args.client,
				Config:        tt.args.config,
				mutableConfig: newMutableTLSConfig(),
			}
			if err := ctx.apply([]TLSOption{AddFederationToCAs()}); (err != nil) != tt.wantErr {
				t.Errorf("AddFederationToCAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(ctx.Config, tt.want) {
				// Federated roots are randomly sorted
				if !equalPools(ctx.Config.ClientCAs, tt.want.ClientCAs) || !equalPools(ctx.Config.RootCAs, tt.want.RootCAs) {
					t.Errorf("AddFederationToCAs() = %v, want %v", ctx.Config, tt.want)
				}
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
