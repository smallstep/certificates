package ca

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"

	"github.com/smallstep/cli/crypto/randutil"
	stepJOSE "github.com/smallstep/cli/jose"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("failed to listen on a port: %v", err))
		}
	}
	return l
}

func setMinCertDuration(d time.Duration) func() {
	tmp := minCertDuration
	minCertDuration = 1 * time.Second
	return func() {
		minCertDuration = tmp
	}
}

func startCABootstrapServer() *httptest.Server {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	if err != nil {
		panic(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	config.Address = srv.Listener.Addr().String()
	ca, err := New(config)
	if err != nil {
		panic(err)
	}
	srv.Config.Handler = ca.srv.Handler
	srv.TLS = ca.srv.TLSConfig
	srv.StartTLS()
	// Force the use of GetCertificate on IPs
	srv.TLS.Certificates = nil
	return srv
}

func generateBootstrapToken(ca, subject, sha string) string {
	now := time.Now()
	jwk, err := stepJOSE.ParseKey("testdata/secrets/ott_mariano_priv.jwk", stepJOSE.WithPassword([]byte("password")))
	if err != nil {
		panic(err)
	}
	opts := new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key}, opts)
	if err != nil {
		panic(err)
	}
	id, err := randutil.ASCII(64)
	if err != nil {
		panic(err)
	}
	cl := struct {
		SHA string `json:"sha"`
		jwt.Claims
	}{
		SHA: sha,
		Claims: jwt.Claims{
			ID:        id,
			Subject:   subject,
			Issuer:    "mariano",
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
			Audience:  []string{ca + "/sign"},
		},
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func TestBootstrap(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	client, err := NewClient(srv.URL+"/sign", WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    *Client
		wantErr bool
	}{
		{"ok", args{token}, client, false},
		{"token err", args{"badtoken"}, nil, true},
		{"bad claims", args{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.foo.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}, nil, true},
		{"bad sha", args{generateBootstrapToken(srv.URL, "subject", "")}, nil, true},
		{"bad aud", args{generateBootstrapToken("", "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Bootstrap(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Bootstrap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Bootstrap() = %v, want %v", got, tt.want)
				}
			} else {
				if got == nil {
					t.Error("Bootstrap() = nil, want not nil")
				} else {
					if !reflect.DeepEqual(got.endpoint, tt.want.endpoint) {
						t.Errorf("Bootstrap() endpoint = %v, want %v", got.endpoint, tt.want.endpoint)
					}
					if !reflect.DeepEqual(got.certPool, tt.want.certPool) {
						t.Errorf("Bootstrap() certPool = %v, want %v", got.certPool, tt.want.certPool)
					}
				}
			}
		})
	}
}

func TestBootstrapServerWithoutMTLS(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}
	type args struct {
		ctx   context.Context
		token string
		base  *http.Server
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{context.Background(), token(), &http.Server{}}, false},
		{"fail", args{context.Background(), "bad-token", &http.Server{}}, true},
		{"fail with TLSConfig", args{context.Background(), token(), &http.Server{TLSConfig: &tls.Config{}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BootstrapServer(tt.args.ctx, tt.args.token, tt.args.base, VerifyClientCertIfGiven())
			if (err != nil) != tt.wantErr {
				t.Errorf("BootstrapServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("BootstrapServer() = %v, want nil", got)
				}
			} else {
				expected := &http.Server{
					TLSConfig: got.TLSConfig,
				}
				if !reflect.DeepEqual(got, expected) {
					t.Errorf("BootstrapServer() = %v, want %v", got, expected)
				}
				if got.TLSConfig == nil || got.TLSConfig.ClientCAs == nil || got.TLSConfig.RootCAs == nil || got.TLSConfig.GetCertificate == nil || got.TLSConfig.GetClientCertificate == nil {
					t.Errorf("BootstrapServer() invalid TLSConfig = %#v", got.TLSConfig)
				}
			}
		})
	}
}

func TestBootstrapServerWithMTLS(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}
	type args struct {
		ctx   context.Context
		token string
		base  *http.Server
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{context.Background(), token(), &http.Server{}}, false},
		{"fail", args{context.Background(), "bad-token", &http.Server{}}, true},
		{"fail with TLSConfig", args{context.Background(), token(), &http.Server{TLSConfig: &tls.Config{}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BootstrapServer(tt.args.ctx, tt.args.token, tt.args.base)
			if (err != nil) != tt.wantErr {
				t.Errorf("BootstrapServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("BootstrapServer() = %v, want nil", got)
				}
			} else {
				expected := &http.Server{
					TLSConfig: got.TLSConfig,
				}
				if !reflect.DeepEqual(got, expected) {
					t.Errorf("BootstrapServer() = %v, want %v", got, expected)
				}
				if got.TLSConfig == nil || got.TLSConfig.ClientCAs == nil || got.TLSConfig.RootCAs == nil || got.TLSConfig.GetCertificate == nil || got.TLSConfig.GetClientCertificate == nil {
					t.Errorf("BootstrapServer() invalid TLSConfig = %#v", got.TLSConfig)
				}
			}
		})
	}
}

func TestBootstrapClient(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}
	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{context.Background(), token()}, false},
		{"fail", args{context.Background(), "bad-token"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BootstrapClient(tt.args.ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("BootstrapClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("BootstrapClient() = %v, want nil", got)
				}
			} else {
				tlsConfig := got.Transport.(*http.Transport).TLSClientConfig
				if tlsConfig == nil || tlsConfig.ClientCAs != nil || tlsConfig.GetClientCertificate == nil || tlsConfig.RootCAs == nil || tlsConfig.GetCertificate != nil {
					t.Errorf("BootstrapClient() invalid Transport = %#v", tlsConfig)
				}
				resp, err := got.Post(srv.URL+"/renew", "application/json", http.NoBody)
				if err != nil {
					t.Errorf("BootstrapClient() failed renewing certificate")
					return
				}
				var renewal api.SignResponse
				if err := readJSON(resp.Body, &renewal); err != nil {
					t.Errorf("BootstrapClient() error reading response: %v", err)
					return
				}
				if renewal.CaPEM.Certificate == nil || renewal.ServerPEM.Certificate == nil {
					t.Errorf("BootstrapClient() invalid renewal response: %v", renewal)
				}
			}
		})
	}
}

func TestBootstrapClientRotation(t *testing.T) {
	reset := setMinCertDuration(1 * time.Second)
	defer reset()

	// Configuration with current root
	config, err := authority.LoadConfiguration("testdata/rotate-ca-0.json")
	if err != nil {
		panic(err)
	}

	// Get local address
	listener := newLocalListener()
	config.Address = listener.Addr().String()
	srvURL := "https://" + listener.Addr().String()

	// Start CA server
	ca, err := New(config)
	if err != nil {
		panic(err)
	}
	go func() {
		ca.srv.Serve(listener)
	}()
	defer ca.Stop()
	time.Sleep(1 * time.Second)

	// doTest does a request that requires mTLS
	doTest := func(client *http.Client) error {
		resp, err := client.Get(srvURL + "/roots")
		if err != nil {
			return errors.New("client.Get() failed getting roots")
		}
		var roots api.RootsResponse
		if err := readJSON(resp.Body, &roots); err != nil {
			return errors.Errorf("client.Get() error reading response: %v", err)
		}
		return nil
	}

	// Create bootstrap client
	token := generateBootstrapToken(srvURL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	client, err := BootstrapClient(context.Background(), token)
	if err != nil {
		t.Errorf("BootstrapClient() error = %v", err)
		return
	}

	// Test with default root
	if err := doTest(client); err != nil {
		t.Errorf("Test with rotate-ca-0.json failed: %v", err)
	}

	// wait for renew
	time.Sleep(5 * time.Second)

	// Reload with configuration with current and future root
	ca.opts.configFile = "testdata/rotate-ca-1.json"
	if err := doReload(ca); err != nil {
		t.Errorf("ca.Reload() error = %v", err)
		return
	}
	if err := doTest(client); err != nil {
		t.Errorf("Test with rotate-ca-1.json failed: %v", err)
	}

	// wait for renew
	time.Sleep(5 * time.Second)

	// Reload with new and old root
	ca.opts.configFile = "testdata/rotate-ca-2.json"
	if err := doReload(ca); err != nil {
		t.Errorf("ca.Reload() error = %v", err)
		return
	}
	if err := doTest(client); err != nil {
		t.Errorf("Test with rotate-ca-2.json failed: %v", err)
	}

	// wait for renew
	time.Sleep(5 * time.Second)

	// Reload with pnly the new root
	ca.opts.configFile = "testdata/rotate-ca-3.json"
	if err := doReload(ca); err != nil {
		t.Errorf("ca.Reload() error = %v", err)
		return
	}
	if err := doTest(client); err != nil {
		t.Errorf("Test with rotate-ca-3.json failed: %v", err)
	}
}

// doReload uses the reload implementation but overwrites the new address with
// the one being used.
func doReload(ca *CA) error {
	config, err := authority.LoadConfiguration(ca.opts.configFile)
	if err != nil {
		return errors.Wrap(err, "error reloading ca")
	}

	newCA, err := New(config, WithPassword(ca.opts.password), WithConfigFile(ca.opts.configFile))
	if err != nil {
		return errors.Wrap(err, "error reloading ca")
	}
	// Use same address in new server
	newCA.srv.Addr = ca.srv.Addr
	return ca.srv.Reload(newCA.srv)
}
