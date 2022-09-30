package ca

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/errs"
)

func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(errors.Wrap(err, "failed to listen on a port"))
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
	baseContext := buildContext(ca.auth, nil, nil, nil)
	srv.Config.Handler = ca.srv.Handler
	srv.Config.BaseContext = func(net.Listener) context.Context {
		return baseContext
	}
	srv.TLS = ca.srv.TLSConfig
	srv.StartTLS()
	// Force the use of GetCertificate on IPs
	srv.TLS.Certificates = nil
	return srv
}

func startCAServer(configFile string) (*CA, string, error) {
	config, err := authority.LoadConfiguration(configFile)
	if err != nil {
		return nil, "", err
	}
	listener := newLocalListener()
	config.Address = listener.Addr().String()
	caURL := "https://" + listener.Addr().String()
	ca, err := New(config)
	if err != nil {
		return nil, "", err
	}
	go func() {
		ca.srv.Serve(listener)
	}()
	return ca, caURL, nil
}

func mTLSMiddleware(next http.Handler, nonAuthenticatedPaths ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			render.JSON(w, api.VersionResponse{
				Version:                     "test",
				RequireClientAuthentication: true,
			})
			return
		}

		for _, s := range nonAuthenticatedPaths {
			if strings.HasPrefix(r.URL.Path, s) || strings.HasPrefix(r.URL.Path, "/1.0"+s) {
				next.ServeHTTP(w, r)
				return
			}
		}
		isMTLS := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		if !isMTLS {
			render.Error(w, errs.Unauthorized("missing peer certificate"))
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func generateBootstrapToken(ca, subject, sha string) string {
	now := time.Now()
	jwk, err := jose.ReadKey("testdata/secrets/ott_mariano_priv.jwk", jose.WithPassword([]byte("password")))
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
		jose.Claims
		SANS []string `json:"sans"`
	}{
		SHA: sha,
		Claims: jose.Claims{
			ID:        id,
			Subject:   subject,
			Issuer:    "mariano",
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
			Audience:  []string{ca + "/sign"},
		},
		SANS: []string{subject},
	}
	raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
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
					gotTR := got.client.GetTransport().(*http.Transport)
					wantTR := tt.want.client.GetTransport().(*http.Transport)
					if !equalPools(gotTR.TLSClientConfig.RootCAs, wantTR.TLSClientConfig.RootCAs) {
						t.Errorf("Bootstrap() certPool = %v, want %v", gotTR.TLSClientConfig.RootCAs, wantTR.TLSClientConfig.RootCAs)
					}
				}
			}
		})
	}
}

//nolint:gosec // insecure test servers
func TestBootstrapServerWithoutMTLS(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}

	mtlsServer := startCABootstrapServer()
	next := mtlsServer.Config.Handler
	mtlsServer.Config.Handler = mTLSMiddleware(next, "/root/", "/sign")
	defer mtlsServer.Close()
	mtlsToken := func() string {
		return generateBootstrapToken(mtlsServer.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
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
		{"ok mtls", args{context.Background(), mtlsToken(), &http.Server{}}, false},
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
				//nolint:govet // not comparing errors
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

//nolint:gosec // insecure test servers
func TestBootstrapServerWithMTLS(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}

	mtlsServer := startCABootstrapServer()
	next := mtlsServer.Config.Handler
	mtlsServer.Config.Handler = mTLSMiddleware(next, "/root/", "/sign")
	defer mtlsServer.Close()
	mtlsToken := func() string {
		return generateBootstrapToken(mtlsServer.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
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
		{"ok mtls", args{context.Background(), mtlsToken(), &http.Server{}}, false},
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
				//nolint:govet // not comparing errors
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

	mtlsServer := startCABootstrapServer()
	next := mtlsServer.Config.Handler
	mtlsServer.Config.Handler = mTLSMiddleware(next, "/root/", "/sign")
	defer mtlsServer.Close()
	mtlsToken := func() string {
		return generateBootstrapToken(mtlsServer.URL, "subject", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
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
		{"ok mtls", args{context.Background(), mtlsToken()}, false},
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
				if renewal.CaPEM.Certificate == nil || renewal.ServerPEM.Certificate == nil || len(renewal.CertChainPEM) == 0 {
					t.Errorf("BootstrapClient() invalid renewal response: %v", renewal)
				}
			}
		})
	}
}

func TestBootstrapClientServerRotation(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skipf("skip until we fix https://github.com/smallstep/certificates/issues/873")
	}
	reset := setMinCertDuration(1 * time.Second)
	defer reset()

	// Configuration with current root
	config, err := authority.LoadConfiguration("testdata/rotate-ca-0.json")
	if err != nil {
		t.Fatal(err)
	}

	// Get local address
	listener := newLocalListener()
	config.Address = listener.Addr().String()
	caURL := "https://" + listener.Addr().String()

	// Start CA server
	ca, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		ca.srv.Serve(listener)
	}()
	defer ca.Stop()
	time.Sleep(1 * time.Second)

	// Create bootstrap server
	token := generateBootstrapToken(caURL, "127.0.0.1", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	//nolint:gosec // insecure test server
	server, err := BootstrapServer(context.Background(), token, &http.Server{
		Addr: ":0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("ok"))
		}),
	}, RequireAndVerifyClientCert())
	if err != nil {
		t.Fatal(err)
	}
	listener = newLocalListener()
	srvURL := "https://" + listener.Addr().String()
	go func() {
		server.ServeTLS(listener, "", "")
	}()
	defer server.Close()
	time.Sleep(1 * time.Second)

	// Create bootstrap client
	token = generateBootstrapToken(caURL, "client", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	client, err := BootstrapClient(context.Background(), token)
	if err != nil {
		t.Errorf("BootstrapClient() error = %v", err)
		return
	}

	// doTest does a request that requires mTLS
	doTest := func(client *http.Client) error {
		// test with ca
		resp, err := client.Post(caURL+"/renew", "application/json", http.NoBody)
		if err != nil {
			return errors.Wrap(err, "client.Post() failed")
		}
		var renew api.SignResponse
		if err := readJSON(resp.Body, &renew); err != nil {
			return errors.Wrap(err, "client.Post() error reading response")
		}
		if renew.ServerPEM.Certificate == nil || renew.CaPEM.Certificate == nil || len(renew.CertChainPEM) == 0 {
			return errors.New("client.Post() unexpected response found")
		}
		// test with bootstrap server
		resp, err = client.Get(srvURL)
		if err != nil {
			return errors.Wrapf(err, "client.Get(%s) failed", srvURL)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "client.Get() error reading response")
		}
		if string(b) != "ok" {
			return errors.New("client.Get() unexpected response found")
		}
		return nil
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

func TestBootstrapClientServerFederation(t *testing.T) {
	reset := setMinCertDuration(1 * time.Second)
	defer reset()

	ca1, caURL1, err := startCAServer("testdata/ca.json")
	if err != nil {
		t.Fatal(err)
	}
	defer ca1.Stop()

	ca2, caURL2, err := startCAServer("testdata/federated-ca.json")
	if err != nil {
		t.Fatal(err)
	}
	defer ca2.Stop()

	// Create bootstrap server
	token := generateBootstrapToken(caURL1, "127.0.0.1", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	//nolint:gosec // insecure test server
	server, err := BootstrapServer(context.Background(), token, &http.Server{
		Addr: ":0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("ok"))
		}),
	}, RequireAndVerifyClientCert(), AddFederationToClientCAs())
	if err != nil {
		t.Fatal(err)
	}
	listener := newLocalListener()
	srvURL := "https://" + listener.Addr().String()
	go func() {
		server.ServeTLS(listener, "", "")
	}()
	defer server.Close()

	// Create bootstrap client
	token = generateBootstrapToken(caURL2, "client", "c86f74bb7eb2eabef45c4f7fc6c146359ed3a5bbad416b31da5dce8093bcbffd")
	client, err := BootstrapClient(context.Background(), token, AddFederationToRootCAs())
	if err != nil {
		t.Errorf("BootstrapClient() error = %v", err)
		return
	}

	// doTest does a request that requires mTLS
	doTest := func(client *http.Client) error {
		// test with ca
		resp, err := client.Post(caURL2+"/renew", "application/json", http.NoBody)
		if err != nil {
			return errors.Wrap(err, "client.Post() failed")
		}
		var renew api.SignResponse
		if err := readJSON(resp.Body, &renew); err != nil {
			return errors.Wrap(err, "client.Post() error reading response")
		}
		if renew.ServerPEM.Certificate == nil || renew.CaPEM.Certificate == nil || len(renew.CertChainPEM) == 0 {
			return errors.New("client.Post() unexpected response found")
		}
		// test with bootstrap server
		resp, err = client.Get(srvURL)
		if err != nil {
			return errors.Wrapf(err, "client.Get(%s) failed", srvURL)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "client.Get() error reading response")
		}
		if string(b) != "ok" {
			return errors.New("client.Get() unexpected response found")
		}
		return nil
	}

	// Test with default root
	if err := doTest(client); err != nil {
		t.Errorf("Test with rotate-ca-0.json failed: %v", err)
	}
}

// doReload uses the reload implementation but overwrites the new address with
// the one being used.
func doReload(ca *CA) error {
	config, err := authority.LoadConfiguration(ca.opts.configFile)
	if err != nil {
		return errors.Wrap(err, "error reloading ca")
	}

	newCA, err := New(config,
		WithPassword(ca.opts.password),
		WithConfigFile(ca.opts.configFile),
		WithDatabase(ca.auth.GetDatabase()))
	if err != nil {
		return errors.Wrap(err, "error reloading ca")
	}
	// Use same address in new server
	newCA.srv.Addr = ca.srv.Addr
	return ca.srv.Reload(newCA.srv)
}

func TestBootstrapListener(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()
	token := func() string {
		return generateBootstrapToken(srv.URL, "127.0.0.1", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}

	mtlsServer := startCABootstrapServer()
	next := mtlsServer.Config.Handler
	mtlsServer.Config.Handler = mTLSMiddleware(next, "/root/", "/sign")
	defer mtlsServer.Close()
	mtlsToken := func() string {
		return generateBootstrapToken(mtlsServer.URL, "127.0.0.1", "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7")
	}

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{token()}, false},
		{"ok mtls", args{mtlsToken()}, false},
		{"fail", args{"bad-token"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := newLocalListener()
			defer inner.Close()
			lis, err := BootstrapListener(context.Background(), tt.args.token, inner)
			if (err != nil) != tt.wantErr {
				t.Errorf("BootstrapListener() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if lis != nil {
					t.Errorf("BootstrapListener() = %v, want nil", lis)
				}
				return
			}
			wg := new(sync.WaitGroup)
			wg.Add(1)
			go func() {
				http.Serve(lis, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("ok"))
				}))
				wg.Done()
			}()
			defer wg.Wait()
			defer lis.Close()

			client, err := BootstrapClient(context.Background(), token())
			if err != nil {
				t.Errorf("BootstrapClient() error = %v", err)
				return
			}
			resp, err := client.Get("https://" + lis.Addr().String())
			if err != nil {
				t.Errorf("client.Get() error = %v", err)
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("io.ReadAll() error = %v", err)
				return
			}
			if string(b) != "ok" {
				t.Errorf("client.Get() = %s, want ok", string(b))
				return
			}
		})
	}
}
