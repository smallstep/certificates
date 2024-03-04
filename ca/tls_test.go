package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
)

func generateOTT(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	jwk, err := jose.ReadKey("testdata/secrets/ott_mariano_priv.jwk", jose.WithPassword([]byte("password")))
	require.NoError(t, err)

	opts := new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key}, opts)
	require.NoError(t, err)

	id, err := randutil.ASCII(64)
	require.NoError(t, err)

	cl := struct {
		jose.Claims
		SANS []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   subject,
			Issuer:    "mariano",
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
			Audience:  []string{"https://127.0.0.1:0/sign"},
		},
		SANS: []string{subject},
	}
	raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
	require.NoError(t, err)

	return raw
}

func startTestServer(baseContext context.Context, tlsConfig *tls.Config, handler http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsConfig
	// Base context MUST be set before the start of the server
	srv.Config.BaseContext = func(l net.Listener) context.Context {
		return baseContext
	}
	srv.StartTLS()
	// Force the use of GetCertificate on IPs
	srv.TLS.Certificates = nil
	return srv
}

func startCATestServer(t *testing.T) *httptest.Server {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	require.NoError(t, err)
	ca, err := New(config)
	require.NoError(t, err)
	// Use a httptest.Server instead
	baseContext := buildContext(ca.auth, nil, nil, nil)
	srv := startTestServer(baseContext, ca.srv.TLSConfig, ca.srv.Handler)
	return srv
}

func sign(t *testing.T, domain string) (*Client, *api.SignResponse, crypto.PrivateKey) {
	t.Helper()
	srv := startCATestServer(t)
	defer srv.Close()
	return signDuration(t, srv, domain, 0)
}

func signDuration(t *testing.T, srv *httptest.Server, domain string, duration time.Duration) (*Client, *api.SignResponse, crypto.PrivateKey) {
	t.Helper()
	req, pk, err := CreateSignRequest(generateOTT(t, domain))
	require.NoError(t, err)

	if duration > 0 {
		req.NotBefore = api.NewTimeDuration(time.Now())
		req.NotAfter = api.NewTimeDuration(req.NotBefore.Time().Add(duration))
	}

	client, err := NewClient(srv.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	require.NoError(t, err)

	sr, err := client.Sign(req)
	require.NoError(t, err)

	return client, sr, pk
}

func serverHandler(t *testing.T, clientDomain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI != "/no-cert" {
			if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
				w.Write([]byte("fail"))
				t.Error("http.Request.TLS does not have peer certificates")
				return
			}
			if req.TLS.PeerCertificates[0].Subject.CommonName != clientDomain {
				w.Write([]byte("fail"))
				t.Errorf("http.Request.TLS.PeerCertificates[0].Subject.CommonName = %s, wants %s", req.TLS.PeerCertificates[0].Subject.CommonName, clientDomain)
				return
			}
			if !reflect.DeepEqual(req.TLS.PeerCertificates[0].DNSNames, []string{clientDomain}) {
				w.Write([]byte("fail"))
				t.Errorf("http.Request.TLS.PeerCertificates[0].DNSNames %v, wants %v", req.TLS.PeerCertificates[0].DNSNames, []string{clientDomain})
				return
			}

			// Add serial number to check rotation
			sum := sha256.Sum256(req.TLS.PeerCertificates[0].Raw)
			w.Header().Set("x-fingerprint", hex.EncodeToString(sum[:]))
		}

		w.Write([]byte("ok"))
	})
}

func TestClient_GetServerTLSConfig_http(t *testing.T) {
	clientDomain := "test.domain"
	client, sr, pk := sign(t, "127.0.0.1")

	// Create mTLS server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err := client.GetServerTLSConfig(ctx, sr, pk)
	if err != nil {
		t.Fatalf("Client.GetServerTLSConfig() error = %v", err)
	}
	srvMTLS := startTestServer(context.Background(), tlsConfig, serverHandler(t, clientDomain))
	defer srvMTLS.Close()

	// Create TLS server
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err = client.GetServerTLSConfig(ctx, sr, pk, VerifyClientCertIfGiven())
	if err != nil {
		t.Fatalf("Client.GetServerTLSConfig() error = %v", err)
	}
	srvTLS := startTestServer(context.Background(), tlsConfig, serverHandler(t, clientDomain))
	defer srvTLS.Close()

	tests := []struct {
		name      string
		getClient func(*testing.T, *Client, *api.SignResponse, crypto.PrivateKey) *http.Client
		wantErr   map[string]bool
	}{
		{"with transport", func(t *testing.T, client *Client, sr *api.SignResponse, pk crypto.PrivateKey) *http.Client {
			tr, err := client.Transport(context.Background(), sr, pk)
			if err != nil {
				t.Errorf("Client.Transport() error = %v", err)
				return nil
			}
			return &http.Client{
				Transport: tr,
			}
		}, map[string]bool{srvTLS.URL: false, srvMTLS.URL: false}},
		{"with tlsConfig", func(t *testing.T, client *Client, sr *api.SignResponse, pk crypto.PrivateKey) *http.Client {
			tlsConfig, err := client.GetClientTLSConfig(context.Background(), sr, pk)
			if err != nil {
				t.Errorf("Client.GetClientTLSConfig() error = %v", err)
				return nil
			}
			return &http.Client{
				Transport: getDefaultTransport(tlsConfig),
			}
		}, map[string]bool{srvTLS.URL: false, srvMTLS.URL: false}},
		{"with no ClientCert", func(t *testing.T, client *Client, sr *api.SignResponse, pk crypto.PrivateKey) *http.Client {
			root, err := RootCertificate(sr)
			if err != nil {
				t.Errorf("RootCertificate() error = %v", err)
				return nil
			}
			tlsConfig := getDefaultTLSConfig(sr)
			tlsConfig.RootCAs = x509.NewCertPool()
			tlsConfig.RootCAs.AddCert(root)
			return &http.Client{
				Transport: getDefaultTransport(tlsConfig),
			}
		}, map[string]bool{srvTLS.URL + "/no-cert": false, srvMTLS.URL + "/no-cert": true}},
		{"fail with default", func(t *testing.T, client *Client, sr *api.SignResponse, pk crypto.PrivateKey) *http.Client {
			return &http.Client{}
		}, map[string]bool{srvTLS.URL + "/no-cert": true, srvMTLS.URL + "/no-cert": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, sr, pk := sign(t, clientDomain)
			cli := tt.getClient(t, client, sr, pk)
			if cli == nil {
				return
			}
			for path, wantErr := range tt.wantErr {
				t.Run(path, func(t *testing.T) {
					resp, err := cli.Get(path)
					if (err != nil) != wantErr {
						t.Errorf("http.Client.Get() error = %v, wantErr %v", err, wantErr)
						return
					}
					if wantErr {
						return
					}
					defer resp.Body.Close()
					b, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatalf("io.ReadAll() error = %v", err)
					}
					if !bytes.Equal(b, []byte("ok")) {
						t.Errorf("response body unexpected, got %s, want ok", b)
					}
				})
			}
		})
	}
}

func TestClient_GetServerTLSConfig_renew(t *testing.T) {
	reset := setMinCertDuration(1 * time.Second)
	defer reset()

	// Start CA
	ca := startCATestServer(t)
	defer ca.Close()

	clientDomain := "test.domain"
	client, sr, pk := signDuration(t, ca, "127.0.0.1", 5*time.Second)

	// Start mTLS server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err := client.GetServerTLSConfig(ctx, sr, pk)
	require.NoError(t, err)

	srvMTLS := startTestServer(context.Background(), tlsConfig, serverHandler(t, clientDomain))
	defer srvMTLS.Close()

	// Start TLS server
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err = client.GetServerTLSConfig(ctx, sr, pk, VerifyClientCertIfGiven())
	require.NoError(t, err)

	srvTLS := startTestServer(context.Background(), tlsConfig, serverHandler(t, clientDomain))
	defer srvTLS.Close()

	// Transport
	client, sr, pk = signDuration(t, ca, clientDomain, 5*time.Second)
	tr1, err := client.Transport(context.Background(), sr, pk)
	require.NoError(t, err)

	// Transport with tlsConfig
	client, sr, pk = signDuration(t, ca, clientDomain, 5*time.Second)
	tlsConfig, err = client.GetClientTLSConfig(context.Background(), sr, pk)
	require.NoError(t, err)

	tr2 := getDefaultTransport(tlsConfig)
	// No client cert
	root, err := RootCertificate(sr)
	require.NoError(t, err)

	tlsConfig = getDefaultTLSConfig(sr)
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(root)
	tr3 := getDefaultTransport(tlsConfig)

	// Disable keep alives to force TLS handshake
	tr1.DisableKeepAlives = true
	tr2.DisableKeepAlives = true
	tr3.DisableKeepAlives = true

	tests := []struct {
		name    string
		client  *http.Client
		wantErr map[string]bool
	}{
		{"with transport", &http.Client{Transport: tr1}, map[string]bool{
			srvTLS.URL:  false,
			srvMTLS.URL: false,
		}},
		{"with tlsConfig", &http.Client{Transport: tr2}, map[string]bool{
			srvTLS.URL:  false,
			srvMTLS.URL: false,
		}},
		{"with no ClientCert", &http.Client{Transport: tr3}, map[string]bool{
			srvTLS.URL + "/no-cert":  false,
			srvMTLS.URL + "/no-cert": true,
		}},
		{"fail with default", &http.Client{}, map[string]bool{
			srvTLS.URL + "/no-cert":  true,
			srvMTLS.URL + "/no-cert": true,
		}},
	}

	// To count different cert fingerprints
	fingerprints := map[string]struct{}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for path, wantErr := range tt.wantErr {
				t.Run(path, func(t *testing.T) {
					resp, err := tt.client.Get(path)
					if (err != nil) != wantErr {
						t.Errorf("http.Client.Get() error = %v", err)
						return
					}
					if wantErr {
						return
					}
					if fp := resp.Header.Get("x-fingerprint"); fp != "" {
						fingerprints[fp] = struct{}{}
					}

					defer resp.Body.Close()
					b, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Errorf("io.ReadAll() error = %v", err)
						return
					}
					if !bytes.Equal(b, []byte("ok")) {
						t.Errorf("response body unexpected, got %s, want ok", b)
						return
					}
				})
			}
		})
	}

	if l := len(fingerprints); l != 2 {
		t.Errorf("number of fingerprints unexpected, got %d, want 2", l)
	}

	// Wait for renewal
	log.Printf("Sleeping for %s ...\n", 5*time.Second)
	time.Sleep(5 * time.Second)

	for _, tt := range tests {
		t.Run("renewed "+tt.name, func(t *testing.T) {
			for path, wantErr := range tt.wantErr {
				t.Run(path, func(t *testing.T) {
					resp, err := tt.client.Get(path)
					if (err != nil) != wantErr {
						t.Errorf("http.Client.Get() error = %v", err)
						return
					}
					if wantErr {
						return
					}
					if fp := resp.Header.Get("x-fingerprint"); fp != "" {
						fingerprints[fp] = struct{}{}
					}

					defer resp.Body.Close()
					b, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Errorf("io.ReadAll() error = %v", err)
						return
					}
					if !bytes.Equal(b, []byte("ok")) {
						t.Errorf("response body unexpected, got %s, want ok", b)
						return
					}
				})
			}
		})
	}

	if l := len(fingerprints); l != 4 {
		t.Errorf("number of fingerprints unexpected, got %d, want 4", l)
	}
}

func TestCertificate(t *testing.T) {
	cert := parseCertificate(t, certPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: cert},
		CaPEM:     api.Certificate{Certificate: parseCertificate(t, rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: cert},
			{Certificate: parseCertificate(t, rootPEM)},
		},
	}
	tests := []struct {
		name    string
		sign    *api.SignResponse
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", ok, cert, false},
		{"fail", &api.SignResponse{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Certificate(tt.sign)
			if (err != nil) != tt.wantErr {
				t.Errorf("Certificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Certificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIntermediateCertificate(t *testing.T) {
	intermediate := parseCertificate(t, rootPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(t, certPEM)},
		CaPEM:     api.Certificate{Certificate: intermediate},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(t, certPEM)},
			{Certificate: intermediate},
		},
	}
	tests := []struct {
		name    string
		sign    *api.SignResponse
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", ok, intermediate, false},
		{"fail", &api.SignResponse{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IntermediateCertificate(tt.sign)
			if (err != nil) != tt.wantErr {
				t.Errorf("IntermediateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IntermediateCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRootCertificateCertificate(t *testing.T) {
	root := parseCertificate(t, rootPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(t, certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(t, rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(t, certPEM)},
			{Certificate: parseCertificate(t, rootPEM)},
		},
		TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{
			{root, root},
		}},
	}
	noTLS := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(t, certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(t, rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(t, certPEM)},
			{Certificate: parseCertificate(t, rootPEM)},
		},
	}
	tests := []struct {
		name    string
		sign    *api.SignResponse
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", ok, root, false},
		{"fail", &api.SignResponse{}, nil, true},
		{"no tls", noTLS, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RootCertificate(tt.sign)
			if (err != nil) != tt.wantErr {
				t.Errorf("RootCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RootCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
