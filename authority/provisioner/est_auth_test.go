package provisioner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/webhook"
)

func mustESTTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestEST_authorizeWithWebhook(t *testing.T) {
	root, rootKey := mustESTTestCert(t, "root", true, nil, nil)
	trusted, _ := mustESTTestCert(t, "trusted", false, root, rootKey)
	otherRoot, otherKey := mustESTTestCert(t, "other", true, nil, nil)
	untrusted, _ := mustESTTestCert(t, "untrusted", false, otherRoot, otherKey)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	pool := x509.NewCertPool()
	pool.AddCert(root)
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}
	enabled, disabled := true, false

	tests := []struct {
		name              string
		enabled           *bool
		req               ESTAuthRequest
		wantCalled        bool
		wantClientCert    bool
		wantBearer        string
		wantDeniedLocally bool
	}{
		{name: "verified certificate reaches the webhook", enabled: &enabled,
			req: ESTAuthRequest{ClientCertificate: trusted}, wantCalled: true, wantClientCert: true},
		{name: "certificate and bearer token are both forwarded", enabled: &enabled,
			req:        ESTAuthRequest{ClientCertificate: trusted, AuthenticationHeader: "Bearer jwt", BearerToken: "jwt"},
			wantCalled: true, wantClientCert: true, wantBearer: "jwt"},
		{name: "untrusted certificate is dropped but the token still authenticates", enabled: &enabled,
			req:        ESTAuthRequest{ClientCertificate: untrusted, AuthenticationHeader: "Bearer jwt", BearerToken: "jwt"},
			wantCalled: true, wantBearer: "jwt"},
		{name: "untrusted certificate alone never reaches the webhook", enabled: &enabled,
			req: ESTAuthRequest{ClientCertificate: untrusted}, wantDeniedLocally: true},
		{name: "certificate is ignored when client certificates are disabled", enabled: &disabled,
			req: ESTAuthRequest{ClientCertificate: trusted}, wantDeniedLocally: true},
		{name: "no credentials never reach the webhook", enabled: &enabled, wantDeniedLocally: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *webhook.RequestBody
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = &webhook.RequestBody{}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(got))
				assert.NoError(t, json.NewEncoder(w).Encode(webhook.ResponseBody{Allow: true}))
			}))
			defer srv.Close()

			s := &EST{
				Name:                       "est",
				EnableTLSClientCertificate: tt.enabled,
				ClientCertificateRoots:     rootPEM,
				clientCertificateRootPool:  pool,
				challengeValidationController: &challengeValidationController{
					client:   srv.Client(),
					webhooks: []*Webhook{{Name: "authz", URL: srv.URL}},
				},
			}
			tt.req.CSR = csr

			opts, err := s.AuthorizeRequest(context.Background(), tt.req)
			if tt.wantDeniedLocally {
				assert.True(t, errors.Is(err, ErrESTAuthDenied), "got %v", err)
				assert.Nil(t, got, "webhook must not be called")
				return
			}
			require.NoError(t, err)
			assert.Len(t, opts, 1)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantClientCert, got.ClientCertificate != nil)
			assert.Equal(t, tt.wantBearer, got.BearerToken)
			assert.Equal(t, "est", got.ProvisionerName)
		})
	}
}
