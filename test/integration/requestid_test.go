package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/ca/client"
	"github.com/smallstep/certificates/errs"
)

// reservePort "reserves" a TCP port by opening a listener on a random
// port and immediately closing it. The port can then be assumed to be
// available for running a server on.
func reservePort(t *testing.T) (host, port string) {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	address := l.Addr().String()
	err = l.Close()
	require.NoError(t, err)

	host, port, err = net.SplitHostPort(address)
	require.NoError(t, err)

	return
}

func Test_reflectRequestID(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	t.Setenv("STEPPATH", dir)

	m, err := minica.New(minica.WithName("Step E2E"))
	require.NoError(t, err)

	rootFilepath := filepath.Join(dir, "root.crt")
	_, err = pemutil.Serialize(m.Root, pemutil.WithFilename(rootFilepath))
	require.NoError(t, err)

	intermediateCertFilepath := filepath.Join(dir, "intermediate.crt")
	_, err = pemutil.Serialize(m.Intermediate, pemutil.WithFilename(intermediateCertFilepath))
	require.NoError(t, err)

	intermediateKeyFilepath := filepath.Join(dir, "intermediate.key")
	_, err = pemutil.Serialize(m.Signer, pemutil.WithFilename(intermediateKeyFilepath))
	require.NoError(t, err)

	// get a random address to listen on and connect to; currently no nicer way to get one before starting the server
	// TODO(hs): find/implement a nicer way to expose the CA URL, similar to how e.g. httptest.Server exposes it?
	host, port := reservePort(t)

	authorizingSrv := newAuthorizingServer(t, m)
	defer authorizingSrv.Close()
	authorizingSrv.StartTLS()

	password := []byte("1234")
	jwk, jwe, err := jose.GenerateDefaultKeyPair(password)
	require.NoError(t, err)
	encryptedKey, err := jwe.CompactSerialize()
	require.NoError(t, err)
	prov := &provisioner.JWK{
		ID:           "jwk",
		Name:         "jwk",
		Type:         "JWK",
		Key:          jwk,
		EncryptedKey: encryptedKey,
		Claims:       &config.GlobalProvisionerClaims,
		Options: &provisioner.Options{
			Webhooks: []*provisioner.Webhook{
				{
					ID:       "webhook",
					Name:     "webhook-test",
					URL:      fmt.Sprintf("%s/authorize", authorizingSrv.URL),
					Kind:     "AUTHORIZING",
					CertType: "X509",
				},
			},
		},
	}
	err = prov.Init(provisioner.Config{})
	require.NoError(t, err)

	cfg := &config.Config{
		Root:             []string{rootFilepath},
		IntermediateCert: intermediateCertFilepath,
		IntermediateKey:  intermediateKeyFilepath,
		Address:          net.JoinHostPort(host, port), // reuse the address that was just "reserved"
		DNSNames:         []string{"127.0.0.1", "[::1]", "localhost"},
		AuthorityConfig: &config.AuthConfig{
			AuthorityID:    "stepca-test",
			DeploymentType: "standalone-test",
			Provisioners:   provisioner.List{prov},
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := ca.New(cfg)
	require.NoError(t, err)

	// instantiate a client for the CA running at the random address
	caClient, err := ca.NewClient(
		fmt.Sprintf("https://localhost:%s", port),
		ca.WithRootFile(rootFilepath),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = c.Run()
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()

	// require the CA server to be available within 10 seconds,
	// failing the test if it doesn't.
	requireCAServerToBeAvailable(t, net.JoinHostPort("localhost", port), 10*time.Second)

	// require OK health response as the baseline
	healthResponse, err := caClient.HealthWithContext(ctx)
	require.NoError(t, err)
	if assert.NotNil(t, healthResponse) {
		require.Equal(t, "ok", healthResponse.Status)
	}

	// expect an error when retrieving an invalid root
	rootResponse, err := caClient.RootWithContext(ctx, "invalid")
	var firstErr *errs.Error
	if assert.ErrorAs(t, err, &firstErr) {
		assert.Equal(t, 404, firstErr.StatusCode())
		assert.Equal(t, `root certificate with fingerprint "invalid" was not found`, firstErr.Err.Error())
		assert.NotEmpty(t, firstErr.RequestID)

	}
	assert.Nil(t, rootResponse)

	// expect an error when retrieving an invalid root and provided request ID
	rootResponse, err = caClient.RootWithContext(client.NewRequestIDContext(ctx, "reqID"), "invalid")
	var secondErr *errs.Error
	if assert.ErrorAs(t, err, &secondErr) {
		assert.Equal(t, 404, secondErr.StatusCode())
		assert.Equal(t, `root certificate with fingerprint "invalid" was not found`, secondErr.Err.Error())
		assert.Equal(t, "reqID", secondErr.RequestID)
	}
	assert.Nil(t, rootResponse)

	// prepare a Sign request
	subject := "test"
	decryptedJWK := decryptPrivateKey(t, jwe, password)
	ott := generateOTT(t, decryptedJWK, subject)

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	csr, err := x509util.CreateCertificateRequest(subject, []string{subject}, signer)
	require.NoError(t, err)

	// perform the Sign request using the OTT and CSR
	signResponse, err := caClient.SignWithContext(client.NewRequestIDContext(ctx, "signRequestID"), &api.SignRequest{
		CsrPEM:    api.CertificateRequest{CertificateRequest: csr},
		OTT:       ott,
		NotAfter:  api.NewTimeDuration(time.Now().Add(1 * time.Hour)),
		NotBefore: api.NewTimeDuration(time.Now().Add(-1 * time.Hour)),
	})
	assert.NoError(t, err)

	// assert a certificate was returned for the subject "test"
	if assert.NotNil(t, signResponse) {
		assert.Len(t, signResponse.CertChainPEM, 2)
		cert, err := x509.ParseCertificate(signResponse.CertChainPEM[0].Raw)
		assert.NoError(t, err)
		if assert.NotNil(t, cert) {
			assert.Equal(t, "test", cert.Subject.CommonName)
			assert.Contains(t, cert.DNSNames, "test")
		}
	}

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}

func decryptPrivateKey(t *testing.T, jwe *jose.JSONWebEncryption, pass []byte) *jose.JSONWebKey {
	t.Helper()
	d, err := jwe.Decrypt(pass)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{}
	err = json.Unmarshal(d, jwk)
	require.NoError(t, err)

	return jwk
}

func generateOTT(t *testing.T, jwk *jose.JSONWebKey, subject string) string {
	t.Helper()
	now := time.Now()

	keyID, err := jose.Thumbprint(jwk)
	require.NoError(t, err)

	opts := new(jose.SignerOptions).WithType("JWT").WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Key: jwk.Key}, opts)
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
			Issuer:    "jwk",
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
			Audience:  []string{"https://127.0.0.1/1.0/sign"},
		},
		SANS: []string{subject},
	}
	raw, err := jose.Signed(signer).Claims(cl).CompactSerialize()
	require.NoError(t, err)

	return raw
}

func newAuthorizingServer(t *testing.T, mca *minica.CA) *httptest.Server {
	t.Helper()

	key, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	csr, err := x509util.CreateCertificateRequest("127.0.0.1", []string{"127.0.0.1"}, key)
	require.NoError(t, err)

	crt, err := mca.SignCSR(csr)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if assert.Equal(t, "signRequestID", r.Header.Get("X-Request-Id")) {
			err := json.NewEncoder(w).Encode(struct{ Allow bool }{Allow: true})
			require.NoError(t, err)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(mca.Root)

	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{crt.Raw, mca.Intermediate.Raw},
				PrivateKey:  key,
				Leaf:        crt,
			},
		},
		ClientCAs:  trustedRoots,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ServerName: "localhost",
	}

	return srv
}

// requireCAServerToBeAvailable tries to connect to address to check a server
// is available. It will retry the connection every ~100ms, until timeout occurs.
// If no connection can be made, the test is failed.
func requireCAServerToBeAvailable(t *testing.T, address string, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for !canConnect(ctx, address) {
		select {
		case <-ctx.Done():
			require.FailNow(t, fmt.Sprintf("CA server failed to start at https://%s within %s", address, timeout.String()))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func canConnect(ctx context.Context, address string) bool {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}

	conn.Close()

	return true
}
