package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/middleware/requestid"
)

type warningAuthority struct {
	authority *authority.Authority
	root      *x509.Certificate
	rootKey   crypto.Signer
	issuer    *x509.Certificate
	issuerKey crypto.Signer
	tokenKey  crypto.Signer
	now       time.Time
}

func newWarningAuthority(t *testing.T, mode apiv1.IssuerValidityLimit) *warningAuthority {
	t.Helper()
	f := &warningAuthority{now: time.Now().UTC().Truncate(time.Second)}
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.rootKey = rootKey
	_, f.issuerKey, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, f.tokenKey, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.root = warningCACertificate(t, "Warning Root", f.now.Add(36*time.Hour), nil, rootKey, rootKey, f.now)
	f.issuer = warningCACertificate(t, "Warning Issuer", f.now.Add(48*time.Hour), f.root, f.issuerKey, rootKey, f.now)
	enableSSH := true
	claims := &provisioner.Claims{
		MinTLSDur:         &provisioner.Duration{Duration: time.Minute},
		DefaultTLSDur:     &provisioner.Duration{Duration: 72 * time.Hour},
		MaxTLSDur:         &provisioner.Duration{Duration: 168 * time.Hour},
		DefaultHostSSHDur: &provisioner.Duration{Duration: 72 * time.Hour},
		MaxHostSSHDur:     &provisioner.Duration{Duration: 168 * time.Hour},
		EnableSSHCA:       &enableSSH,
	}
	f.authority, err = authority.NewEmbedded(
		authority.WithConfig(&config.Config{
			DNSNames: []string{"warning.example"},
			AuthorityConfig: &config.AuthConfig{
				Options: &apiv1.Options{IssuerValidityLimit: mode},
				Provisioners: provisioner.List{
					&provisioner.JWK{Type: "JWK", Name: "warning", Key: &jose.JSONWebKey{KeyID: "warning-key", Key: f.tokenKey.Public()}, Claims: claims},
					&provisioner.SSHPOP{Type: "SSHPOP", Name: "sshpop", Claims: claims},
				},
			},
		}),
		authority.WithX509RootCerts(f.root),
		authority.WithX509SignerFunc(func() ([]*x509.Certificate, crypto.Signer, error) {
			return []*x509.Certificate{f.issuer}, f.issuerKey, nil
		}),
		authority.WithSSHHostSigner(f.issuerKey),
		authority.WithSSHUserSigner(f.issuerKey),
		authority.WithQuietInit(),
	)
	require.NoError(t, err)
	return f
}

func warningCACertificate(t *testing.T, name string, expiry time.Time, parent *x509.Certificate, key, signer crypto.Signer, now time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(expiry.Unix()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: expiry, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func warningToken(t *testing.T, key crypto.Signer, opts *jose.SignerOptions, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, opts)
	require.NoError(t, err)
	token, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

func (f *warningAuthority) token(t *testing.T, path string, sshOptions *provisioner.SignSSHOptions) string {
	t.Helper()
	claims := map[string]any{
		"jti": uuid.NewString(), "iss": "warning", "sub": "warning.example",
		"aud": []string{"https://warning.example" + path},
		"nbf": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
		"sans": []string{"warning.example"},
	}
	if sshOptions != nil {
		claims["step"] = map[string]any{"ssh": sshOptions}
		// The same token also authorizes the X.509 identity.
		claims["aud"] = []string{"https://warning.example" + path, "https://warning.example/sign"}
	}
	return warningToken(t, f.tokenKey, new(jose.SignerOptions).WithType("JWT").WithHeader("kid", "warning-key"), claims)
}

func (f *warningAuthority) request(t *testing.T, path string, body any, peer *x509.Certificate) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://warning.example"+path, bytes.NewReader(mustJSON(t, body)))
	r = r.WithContext(authority.NewContext(requestid.NewContext(r.Context(), uuid.NewString()), f.authority))
	if peer != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	return r
}

func assertIssuedWarning(t *testing.T, leaf, issuer, limiting *x509.Certificate, warnings []apiv1.CertificateWarning) {
	t.Helper()
	require.NoError(t, leaf.CheckSignatureFrom(issuer))
	assert.Equal(t, limiting.NotAfter, leaf.NotAfter)
	require.Len(t, warnings, 1)
	warning := warnings[0]
	assert.Equal(t, "issuer_validity_truncated", warning.Code)
	assert.True(t, warning.RequestedNotAfter.After(warning.EffectiveNotAfter))
	assert.Equal(t, leaf.NotAfter, warning.EffectiveNotAfter)
	assert.Equal(t, limiting.NotAfter, warning.LimitingCertificate.NotAfter)
	assert.Equal(t, limiting.Subject.String(), warning.LimitingCertificate.Subject)
	fingerprint := sha256.Sum256(limiting.Raw)
	assert.Equal(t, hex.EncodeToString(fingerprint[:]), warning.LimitingCertificate.Fingerprint)
}

func TestIssuerValidityWarnings(t *testing.T) {
	for _, configuredLogger := range []bool{false, true} {
		t.Run(strconv.FormatBool(configuredLogger), func(t *testing.T) {
			f := newWarningAuthority(t, "")
			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, key)
			require.NoError(t, err)
			logger, hook := logtest.NewNullLogger()
			var fallback bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&fallback)
			t.Cleanup(func() { log.SetOutput(previous) })
			for _, expiry := range []time.Time{f.now.Add(72 * time.Hour), f.now.Add(time.Hour), f.root.NotAfter} {
				fallback.Reset()
				hook.Reset()
				request := f.request(t, "/sign", SignRequest{CsrPEM: NewCertificateRequest(csr), OTT: f.token(t, "/sign", nil), NotAfter: NewTimeDuration(expiry)}, nil)
				var handler http.Handler = http.HandlerFunc(Sign)
				if configuredLogger {
					handler = logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, handler)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, request)
				require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
				var response SignResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				require.NoError(t, response.ServerPEM.CheckSignatureFrom(f.issuer))
				if expiry.After(f.root.NotAfter) {
					assertIssuedWarning(t, response.ServerPEM.Certificate, f.issuer, f.root, response.Warnings)
					assert.Equal(t, expiry, response.Warnings[0].RequestedNotAfter)
				} else {
					assert.Equal(t, expiry, response.ServerPEM.NotAfter)
					assert.Empty(t, response.Warnings)
					var payload map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
					assert.NotContains(t, payload, "warnings")
				}
				if configuredLogger {
					require.Len(t, hook.AllEntries(), 1)
					entry := hook.LastEntry()
					id, _ := requestid.FromContext(request.Context())
					assert.Equal(t, id, entry.Data["request-id"])
					if len(response.Warnings) > 0 {
						assert.Equal(t, logrus.WarnLevel, entry.Level)
						assert.Equal(t, response.Warnings, entry.Data["certificate-warnings"])
					} else {
						assert.Equal(t, logrus.InfoLevel, entry.Level)
						assert.NotContains(t, entry.Data, "certificate-warnings")
					}
					assert.Empty(t, fallback.String())
				} else {
					assert.Equal(t, len(response.Warnings), strings.Count(fallback.String(), "WARNING:"))
				}
			}
		})
	}
	t.Run("reject has no successful warning", func(t *testing.T) {
		f := newWarningAuthority(t, apiv1.IssuerValidityLimitReject)
		csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, f.tokenKey)
		require.NoError(t, err)
		logger, hook := logtest.NewNullLogger()
		request := f.request(t, "/sign", SignRequest{CsrPEM: NewCertificateRequest(csr), OTT: f.token(t, "/sign", nil), NotAfter: NewTimeDuration(f.now.Add(72 * time.Hour))}, nil)
		w := httptest.NewRecorder()
		logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, http.HandlerFunc(Sign)).ServeHTTP(w, request)
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		var response map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.NotContains(t, response, "warnings")
		require.Len(t, hook.AllEntries(), 1)
		assert.NotContains(t, hook.LastEntry().Data, "certificate-warnings")
	})
}

func TestCertificateWarnings_RequestSeparation(t *testing.T) {
	f := newWarningAuthority(t, "")
	csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, f.tokenKey)
	require.NoError(t, err)
	logger, hook := logtest.NewNullLogger()
	handler := logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, http.HandlerFunc(Sign))
	requests := make([]*http.Request, 8)
	responses := make([]*httptest.ResponseRecorder, len(requests))
	for i := range requests {
		expiry := f.now.Add(time.Hour)
		if i%2 == 0 {
			expiry = f.now.Add(72 * time.Hour)
		}
		requests[i] = f.request(t, "/sign", SignRequest{CsrPEM: NewCertificateRequest(csr), OTT: f.token(t, "/sign", nil), NotAfter: NewTimeDuration(expiry)}, nil)
		responses[i] = httptest.NewRecorder()
	}
	var group sync.WaitGroup
	for i := range requests {
		group.Go(func() { handler.ServeHTTP(responses[i], requests[i]) })
	}
	group.Wait()
	entries := hook.AllEntries()
	require.Len(t, entries, len(requests))
	byID := make(map[string]*logrus.Entry, len(entries))
	for _, entry := range entries {
		byID[entry.Data["request-id"].(string)] = entry
	}
	for i, response := range responses {
		require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
		var body SignResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		id, _ := requestid.FromContext(requests[i].Context())
		entry := byID[id]
		require.NotNil(t, entry)
		if i%2 == 0 {
			assertIssuedWarning(t, body.ServerPEM.Certificate, f.issuer, f.root, body.Warnings)
			assert.Equal(t, body.Warnings, entry.Data["certificate-warnings"])
			assert.Equal(t, logrus.WarnLevel, entry.Level)
		} else {
			assert.Empty(t, body.Warnings)
			assert.NotContains(t, entry.Data, "certificate-warnings")
			assert.Equal(t, logrus.InfoLevel, entry.Level)
		}
	}
}

func TestIssuerValidityWarnings_RenewAndRekey(t *testing.T) {
	f := newWarningAuthority(t, "")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, key)
	require.NoError(t, err)
	ctx := authority.NewContext(context.Background(), f.authority)
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	opts, err := f.authority.Authorize(ctx, f.token(t, "/sign", nil))
	require.NoError(t, err)
	oldChain, err := f.authority.SignWithContext(ctx, csr, provisioner.SignOptions{NotAfter: NewTimeDuration(f.now.Add(time.Hour))}, opts...)
	require.NoError(t, err)
	// Rotate to a genuinely signed shorter-lived issuer, retaining its key/name.
	// The original one-hour leaf remains valid for both mTLS and token renewal.
	replacement := warningCACertificate(t, f.issuer.Subject.CommonName, f.now.Add(30*time.Minute), f.root, f.issuerKey, f.rootKey, f.now)
	service, err := authority.NewEmbedded(
		authority.WithConfig(&config.Config{DNSNames: []string{"warning.example"}, AuthorityConfig: &config.AuthConfig{Provisioners: provisioner.List{
			&provisioner.JWK{Type: "JWK", Name: "warning", Key: &jose.JSONWebKey{KeyID: "warning-key", Key: f.tokenKey.Public()}},
		}}}),
		authority.WithX509RootCerts(f.root), authority.WithX509Signer(replacement, f.issuerKey), authority.WithQuietInit(),
	)
	require.NoError(t, err)
	f.authority = service
	for _, mode := range []string{"mtls", "token", "rekey"} {
		t.Run(mode, func(t *testing.T) {
			var body any = struct{}{}
			path := "/renew"
			peer := oldChain[0]
			var handler http.Handler = http.HandlerFunc(Renew)
			wantKey := key.Public()
			if mode == "rekey" {
				_, newKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				newCSR, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, newKey)
				require.NoError(t, err)
				body, path, handler, wantKey = RekeyRequest{CsrPEM: NewCertificateRequest(newCSR)}, "/rekey", http.HandlerFunc(Rekey), newKey.Public()
			}
			r := f.request(t, path, body, peer)
			if mode == "token" {
				r.TLS = nil
				claims := jose.Claims{ID: uuid.NewString(), Subject: peer.Subject.CommonName, Issuer: "step-ca-client/1.0", Audience: []string{"https://warning.example/renew"}, NotBefore: jose.NewNumericDate(f.now), Expiry: jose.NewNumericDate(f.now.Add(time.Minute))}
				token := warningToken(t, key, new(jose.SignerOptions).WithType("JWT").WithHeader("x5cInsecure", []string{base64.StdEncoding.EncodeToString(peer.Raw), base64.StdEncoding.EncodeToString(f.issuer.Raw)}), claims)
				r.Header.Set("Authorization", "Bearer "+token)
			}
			logger, hook := logtest.NewNullLogger()
			w := httptest.NewRecorder()
			logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, handler).ServeHTTP(w, r)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			var response SignResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assertIssuedWarning(t, response.ServerPEM.Certificate, replacement, replacement, response.Warnings)
			assert.Equal(t, wantKey, response.ServerPEM.PublicKey)
			require.Len(t, hook.AllEntries(), 1)
			assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
			assert.Equal(t, response.Warnings, hook.LastEntry().Data["certificate-warnings"])
		})
	}
}

func TestIssuerValidityWarnings_RenewAndRekeyRejection(t *testing.T) {
	f := newWarningAuthority(t, "")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, key)
	require.NoError(t, err)
	ctx := authority.NewContext(context.Background(), f.authority)
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	opts, err := f.authority.Authorize(ctx, f.token(t, "/sign", nil))
	require.NoError(t, err)
	oldChain, err := f.authority.SignWithContext(ctx, csr, provisioner.SignOptions{NotAfter: NewTimeDuration(f.now.Add(time.Hour))}, opts...)
	require.NoError(t, err)

	// Rotate to a shorter-lived replacement issuer under reject mode, as in
	// TestIssuerValidityWarnings_RenewAndRekey: renewal keeps the original
	// one-hour duration, which now exceeds the replacement's remaining life,
	// so the request must be rejected before renewal signing or persistence.
	replacement := warningCACertificate(t, f.issuer.Subject.CommonName, f.now.Add(30*time.Minute), f.root, f.issuerKey, f.rootKey, f.now)
	service, err := authority.NewEmbedded(
		authority.WithConfig(&config.Config{DNSNames: []string{"warning.example"}, AuthorityConfig: &config.AuthConfig{Options: &apiv1.Options{IssuerValidityLimit: apiv1.IssuerValidityLimitReject}, Provisioners: provisioner.List{
			&provisioner.JWK{Type: "JWK", Name: "warning", Key: &jose.JSONWebKey{KeyID: "warning-key", Key: f.tokenKey.Public()}},
		}}}),
		authority.WithX509RootCerts(f.root), authority.WithX509Signer(replacement, f.issuerKey), authority.WithQuietInit(),
	)
	require.NoError(t, err)
	f.authority = service

	for _, mode := range []string{"mtls", "rekey"} {
		t.Run(mode, func(t *testing.T) {
			var body any = struct{}{}
			path := "/renew"
			var handler http.Handler = http.HandlerFunc(Renew)
			if mode == "rekey" {
				_, newKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				newCSR, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, newKey)
				require.NoError(t, err)
				body, path, handler = RekeyRequest{CsrPEM: NewCertificateRequest(newCSR)}, "/rekey", http.HandlerFunc(Rekey)
			}
			logger, hook := logtest.NewNullLogger()
			r := f.request(t, path, body, oldChain[0])
			w := httptest.NewRecorder()
			logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, handler).ServeHTTP(w, r)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			var response struct {
				Status  int    `json:"status"`
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			// The safe policy diagnostic carries both timestamps rather than
			// a generic internal error, without any success-warning metadata.
			require.Equal(t, http.StatusForbidden, response.Status)
			assert.Contains(t, response.Message, "requested certificate expiration ")
			assert.Contains(t, response.Message, replacement.NotAfter.UTC().Truncate(time.Second).Format(time.RFC3339))
			var payload map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
			assert.NotContains(t, payload, "warnings")
			require.Len(t, hook.AllEntries(), 1)
			assert.NotContains(t, hook.LastEntry().Data, "certificate-warnings")
		})
	}
}
func TestIssuerValidityWarnings_ServerRenewRekey(t *testing.T) {
	f := newWarningAuthority(t, "")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, key)
	require.NoError(t, err)
	ctx := authority.NewContext(context.Background(), f.authority)
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	opts, err := f.authority.Authorize(ctx, f.token(t, "/sign", nil))
	require.NoError(t, err)
	// A one-hour leaf: renewal keeps that duration, which exceeds the
	// shorter replacement issuer below, forcing the cap over a real handshake.
	oldChain, err := f.authority.SignWithContext(ctx, csr, provisioner.SignOptions{NotAfter: NewTimeDuration(f.now.Add(time.Hour))}, opts...)
	require.NoError(t, err)
	// Rotate to a genuinely signed shorter-lived issuer, retaining its key/name.
	replacement := warningCACertificate(t, f.issuer.Subject.CommonName, f.now.Add(30*time.Minute), f.root, f.issuerKey, f.rootKey, f.now)
	service, err := authority.NewEmbedded(
		authority.WithConfig(&config.Config{DNSNames: []string{"warning.example"}, AuthorityConfig: &config.AuthConfig{Provisioners: provisioner.List{
			&provisioner.JWK{Type: "JWK", Name: "warning", Key: &jose.JSONWebKey{KeyID: "warning-key", Key: f.tokenKey.Public()}},
		}}}),
		authority.WithX509RootCerts(f.root), authority.WithX509Signer(replacement, f.issuerKey), authority.WithQuietInit(),
	)
	require.NoError(t, err)
	f.authority = service

	// A real TLS server with client-certificate authentication: the peer
	// certificate is presented through an actual handshake, not an injected
	// r.TLS ConnectionState.
	// The test server needs its own certificate with an IP SAN for
	// 127.0.0.1, signed by the same issuer so the client trusts it.
	serverDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1000), Subject: pkix.Name{CommonName: "warning-server"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(2 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, f.issuer, f.issuerKey.Public(), f.issuerKey)
	require.NoError(t, err)
	serverLeaf, err := x509.ParseCertificate(serverDER)
	require.NoError(t, err)
	serverCert := tls.Certificate{Certificate: [][]byte{serverLeaf.Raw, f.issuer.Raw}, PrivateKey: f.issuerKey, Leaf: serverLeaf}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(authority.NewContext(r.Context(), f.authority))
		if r.URL.Path == "/renew" {
			Renew(w, r)
			return
		}
		Rekey(w, r)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	clientCert := tls.Certificate{Certificate: [][]byte{oldChain[0].Raw, f.issuer.Raw}, PrivateKey: key, Leaf: oldChain[0]}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(f.root)
	clientPool.AddCert(f.issuer)
	client := server.Client()
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      clientPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}}

	t.Run("renew", func(t *testing.T) {
		resp, err := client.Post(server.URL+"/renew", "application/json", bytes.NewReader([]byte("{}")))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var body SignResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assertIssuedWarning(t, body.ServerPEM.Certificate, replacement, replacement, body.Warnings)
		assert.Equal(t, key.Public(), body.ServerPEM.PublicKey, "renew preserves the key")
	})
	t.Run("rekey", func(t *testing.T) {
		_, newKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		newCSR, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, newKey)
		require.NoError(t, err)
		csrBody, err := json.Marshal(RekeyRequest{CsrPEM: NewCertificateRequest(newCSR)})
		require.NoError(t, err)
		resp, err := client.Post(server.URL+"/rekey", "application/json", bytes.NewReader(csrBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var body SignResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assertIssuedWarning(t, body.ServerPEM.Certificate, replacement, replacement, body.Warnings)
		assert.Equal(t, newKey.Public(), body.ServerPEM.PublicKey, "rekey replaces the key")
	})
}
