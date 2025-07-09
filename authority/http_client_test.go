package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/internal/httptransport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

func mustCertificate(t *testing.T, a *Authority, csr *x509.CertificateRequest) []*x509.Certificate {
	t.Helper()

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)

	now := time.Now()
	signOpts := provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(now),
		NotAfter:  provisioner.NewTimeDuration(now.Add(5 * time.Minute)),
		Backdate:  1 * time.Minute,
	}

	sans := []string{}
	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, s := range csr.IPAddresses {
		sans = append(sans, s.String())
	}
	for _, s := range csr.URIs {
		sans = append(sans, s.String())
	}

	key, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	require.NoError(t, err)

	token, err := generateToken(csr.Subject.CommonName, "step-cli", testAudiences.Sign[0], sans, now, key)
	require.NoError(t, err)

	extraOpts, err := a.Authorize(ctx, token)
	require.NoError(t, err)

	chain, err := a.SignWithContext(ctx, csr, signOpts, extraOpts...)
	require.NoError(t, err)

	return chain
}

func Test_newHTTPClient(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	csr, err := x509util.CreateCertificateRequest("test", []string{"localhost", "127.0.0.1", "[::1]"}, signer)
	require.NoError(t, err)

	auth := testAuthority(t)
	chain := mustCertificate(t, auth, csr)

	t.Run("SystemCertPool", func(t *testing.T) {
		resp, err := auth.httpClient.Get("https://smallstep.com")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.NotEmpty(t, b)
		assert.NoError(t, resp.Body.Close())
	})

	t.Run("LocalCertPool", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "ok")
		}))
		srv.TLS = &tls.Config{
			Certificates: []tls.Certificate{
				{Certificate: [][]byte{chain[0].Raw, chain[1].Raw}, PrivateKey: signer, Leaf: chain[0]},
			},
		}
		srv.StartTLS()
		defer srv.Close()

		resp, err := auth.httpClient.Get(srv.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), b)
		assert.NoError(t, resp.Body.Close())

		t.Run("DefaultClient", func(t *testing.T) {
			client := &http.Client{}
			_, err := client.Get(srv.URL)
			assert.Error(t, err)
		})
	})

	t.Run("custom transport", func(t *testing.T) {
		tmp := http.DefaultTransport
		t.Cleanup(func() {
			http.DefaultTransport = tmp
		})
		transport := struct {
			http.RoundTripper
		}{http.DefaultTransport}
		http.DefaultTransport = transport

		client := newHTTPClient(httptransport.NoopWrapper(), auth.rootX509Certs...)
		assert.NotNil(t, client)
	})
}
