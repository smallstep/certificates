package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/ca-component/api"
	"github.com/smallstep/ca-component/authority"
	"github.com/smallstep/cli/crypto/randutil"
	stepJOSE "github.com/smallstep/cli/jose"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func generateOTT(subject string) string {
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
	cl := jwt.Claims{
		ID:        id,
		Subject:   subject,
		Issuer:    "mariano",
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://127.0.0.1:0/sign"},
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func startTestServer(tlsConfig *tls.Config, handler http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsConfig
	srv.StartTLS()
	// Force the use of GetCertificate on IPs
	srv.TLS.Certificates = nil
	return srv
}

func startCATestServer() *httptest.Server {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	if err != nil {
		panic(err)
	}
	ca, err := New(config)
	if err != nil {
		panic(err)
	}
	// Use a httptest.Server instead
	return startTestServer(ca.srv.TLSConfig, ca.srv.Handler)
}

func sign(domain string) (*Client, *api.SignResponse, crypto.PrivateKey) {
	srv := startCATestServer()
	defer srv.Close()
	return signDuration(srv, domain, 0)
}

func signDuration(srv *httptest.Server, domain string, duration time.Duration) (*Client, *api.SignResponse, crypto.PrivateKey) {
	req, pk, err := CreateSignRequest(generateOTT(domain))
	if err != nil {
		panic(err)
	}

	if duration > 0 {
		req.NotBefore = time.Now()
		req.NotAfter = req.NotBefore.Add(duration)
	}

	client, err := NewClient(srv.URL, WithRootFile("testdata/secrets/root_ca.crt"))
	if err != nil {
		panic(err)
	}
	sr, err := client.Sign(req)
	if err != nil {
		panic(err)
	}
	return client, sr, pk
}

func TestClient_GetServerTLSConfig_http(t *testing.T) {
	client, sr, pk := sign("127.0.0.1")
	tlsConfig, err := client.GetServerTLSConfig(context.Background(), sr, pk)
	if err != nil {
		t.Fatalf("Client.GetServerTLSConfig() error = %v", err)
	}
	clientDomain := "test.domain"
	// Create server with given tls.Config
	srv := startTestServer(tlsConfig, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tests := []struct {
		name      string
		getClient func(*testing.T, *Client, *api.SignResponse, crypto.PrivateKey) *http.Client
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
		}},
		{"with tlsConfig", func(t *testing.T, client *Client, sr *api.SignResponse, pk crypto.PrivateKey) *http.Client {
			tlsConfig, err := client.GetClientTLSConfig(context.Background(), sr, pk)
			if err != nil {
				t.Errorf("Client.GetClientTLSConfig() error = %v", err)
				return nil
			}
			tr, err := getDefaultTransport(tlsConfig)
			if err != nil {
				t.Errorf("getDefaultTransport() error = %v", err)
				return nil
			}
			return &http.Client{
				Transport: tr,
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, sr, pk := sign(clientDomain)
			cli := tt.getClient(t, client, sr, pk)
			if cli != nil {
				resp, err := cli.Get(srv.URL)
				if err != nil {
					t.Fatalf("http.Client.Get() error = %v", err)
				}
				defer resp.Body.Close()
				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("ioutil.RealAdd() error = %v", err)
				}
				if !bytes.Equal(b, []byte("ok")) {
					t.Errorf("response body unexpected, got %s, want ok", b)
				}
			}
		})
	}
}

func TestClient_GetServerTLSConfig_renew(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	// Start CA
	ca := startCATestServer()
	defer ca.Close()

	client, sr, pk := signDuration(ca, "127.0.0.1", 1*time.Minute)
	tlsConfig, err := client.GetServerTLSConfig(context.Background(), sr, pk)
	if err != nil {
		t.Fatalf("Client.GetServerTLSConfig() error = %v", err)
	}
	clientDomain := "test.domain"
	fingerprints := make(map[string]struct{})

	// Create server with given tls.Config
	srv := startTestServer(tlsConfig, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
		fingerprints[hex.EncodeToString(sum[:])] = struct{}{}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Clients: transport and tlsConfig
	client, sr, pk = signDuration(ca, clientDomain, 1*time.Minute)
	tr1, err := client.Transport(context.Background(), sr, pk)
	if err != nil {
		t.Fatalf("Client.Transport() error = %v", err)
	}
	client, sr, pk = signDuration(ca, clientDomain, 1*time.Minute)
	tlsConfig, err = client.GetClientTLSConfig(context.Background(), sr, pk)
	if err != nil {
		t.Fatalf("Client.GetClientTLSConfig() error = %v", err)
	}
	tr2, err := getDefaultTransport(tlsConfig)
	if err != nil {
		t.Fatalf("getDefaultTransport() error = %v", err)
	}

	// Disable keep alives to force TLS handshake
	tr1.DisableKeepAlives = true
	tr2.DisableKeepAlives = true

	tests := []struct {
		name   string
		client *http.Client
	}{
		{"with transport", &http.Client{Transport: tr1}},
		{"with tlsConfig", &http.Client{Transport: tr2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(srv.URL)
			if err != nil {
				t.Fatalf("http.Client.Get() error = %v", err)
			}
			defer resp.Body.Close()
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ioutil.RealAdd() error = %v", err)
			}
			if !bytes.Equal(b, []byte("ok")) {
				t.Errorf("response body unexpected, got %s, want ok", b)
			}
		})
	}

	if l := len(fingerprints); l != 2 {
		t.Errorf("number of fingerprints unexpected, got %d, want 4", l)
	}

	// Wait for renewal 40s == 1m-1m/3
	log.Printf("Sleeping for %s ...\n", 40*time.Second)
	time.Sleep(40 * time.Second)

	for _, tt := range tests {
		t.Run("renewed "+tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(srv.URL)
			if err != nil {
				t.Fatalf("http.Client.Get() error = %v", err)
			}
			defer resp.Body.Close()
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ioutil.RealAdd() error = %v", err)
			}
			if !bytes.Equal(b, []byte("ok")) {
				t.Errorf("response body unexpected, got %s, want ok", b)
			}
		})
	}

	if l := len(fingerprints); l != 4 {
		t.Errorf("number of fingerprints unexpected, got %d, want 4", l)
	}
}

func TestCertificate(t *testing.T) {
	cert := parseCertificate(certPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: cert},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
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
	intermediate := parseCertificate(rootPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: intermediate},
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
	root := parseCertificate(rootPEM)
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
		TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{
			{root, root},
		}},
	}
	noTLS := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
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
