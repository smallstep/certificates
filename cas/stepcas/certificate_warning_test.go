package stepcas

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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/logging"
)

func TestIssuerValidityWarnings_StepCAS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootTemplate := *testRootCrt
	rootTemplate.NotBefore = now.Add(-time.Hour)
	rootTemplate.NotAfter = now.Add(time.Hour)
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, testRootKey.Public(), testRootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	issuerTemplate := *testIssCrt
	issuerTemplate.NotBefore = now.Add(-time.Hour)
	issuerTemplate.NotAfter = now.Add(2 * time.Hour)
	issuerDER, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, root, testIssKey.Public(), testRootKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)
	chain := []*x509.Certificate{issuer}
	provisioners := func() provisioner.List {
		return provisioner.List{&provisioner.JWK{
			Type: "JWK", Name: "ra@doe.org", Key: &jose.JSONWebKey{KeyID: testKeyID, Key: testX5CKey.Public()},
			Claims: &provisioner.Claims{
				MinTLSDur:     &provisioner.Duration{Duration: time.Minute},
				DefaultTLSDur: &provisioner.Duration{Duration: 2 * time.Hour},
				MaxTLSDur:     &provisioner.Duration{Duration: 4 * time.Hour},
			},
		}}
	}
	upstream, err := authority.NewEmbedded(
		authority.WithConfig(&config.Config{DNSNames: []string{"127.0.0.1"}, AuthorityConfig: &config.AuthConfig{Provisioners: provisioners()}}),
		authority.WithX509RootCerts(root),
		authority.WithX509SignerFunc(func() ([]*x509.Certificate, crypto.Signer, error) { return chain, testIssKey, nil }),
		authority.WithQuietInit(),
	)
	require.NoError(t, err)
	logger, hook := logtest.NewNullLogger()
	handler := logging.NewLoggerHandler("upstream", &logging.Logger{Logger: logger}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(authority.NewContext(r.Context(), upstream))
		switch r.URL.Path {
		case "/sign":
			api.Sign(w, r)
		case "/renew":
			api.Renew(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	// The transport trust certificate is unrelated to the issuing CA and expires
	// earlier. StepCAS must propagate policy from the upstream, not this trust path.
	_, transportKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	transportTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Unrelated RA transport trust"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, transportTemplate, transportTemplate, transportKey.Public(), transportKey)
	require.NoError(t, err)
	transportCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: transportKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(transportCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	client, err := ca.NewClient(server.URL, ca.WithTransport(transport))
	require.NoError(t, err)
	upstreamURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	iss, err := newJWKIssuer(context.Background(), upstreamURL, client, &apiv1.CertificateIssuer{Type: "jwk", Provisioner: "ra@doe.org", Key: testX5CKeyPath})
	require.NoError(t, err)
	ra := &StepCAS{iss: iss, client: client, authorityID: "downstream-authority"}
	template := &x509.Certificate{Subject: testCR.Subject, DNSNames: testCR.DNSNames, EmailAddresses: testCR.EmailAddresses, IPAddresses: testCR.IPAddresses, URIs: testCR.URIs}

	issued, err := ra.CreateCertificate(&apiv1.CreateCertificateRequest{CSR: testCR, Template: template, Lifetime: 2 * time.Hour})
	require.NoError(t, err)
	require.NoError(t, issued.Certificate.CheckSignatureFrom(issuer))
	assert.Equal(t, root.NotAfter, issued.Certificate.NotAfter)
	assert.True(t, issued.Certificate.NotAfter.After(transportCert.NotAfter))
	require.Len(t, issued.Warnings, 1)
	assert.Equal(t, issued.Warnings, hook.LastEntry().Data["certificate-warnings"])
	fingerprint := sha256.Sum256(root.Raw)
	assert.Equal(t, hex.EncodeToString(fingerprint[:]), issued.Warnings[0].LimitingCertificate.Fingerprint)
	assert.Equal(t, "issuer_validity_truncated", issued.Warnings[0].Code)
	assert.Equal(t, issued.Certificate.NotAfter, issued.Warnings[0].EffectiveNotAfter)

	// Exercise the downstream native handler as well as direct CAS consumers.
	downstream, err := authority.NewEmbedded(
		authority.WithConfig(&config.Config{DNSNames: []string{"downstream.example"}, AuthorityConfig: &config.AuthConfig{Provisioners: provisioners()}}),
		authority.WithX509RootCerts(transportCert), authority.WithX509CAService(ra), authority.WithQuietInit(),
	)
	require.NoError(t, err)
	downstreamIssuer := *iss
	downstreamIssuer.caURL, err = url.Parse("https://downstream.example")
	require.NoError(t, err)
	token, err := downstreamIssuer.SignToken(template.Subject.CommonName, append(append(append([]string{}, template.DNSNames...), template.EmailAddresses...), "127.0.0.1", "::1", template.URIs[0].String()), nil)
	require.NoError(t, err)
	body, err := json.Marshal(api.SignRequest{CsrPEM: api.NewCertificateRequest(testCR), OTT: token, NotAfter: api.NewTimeDuration(now.Add(2 * time.Hour))})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "https://downstream.example/sign", bytes.NewReader(body))
	request = request.WithContext(authority.NewContext(request.Context(), downstream))
	downstreamLogger, downstreamHook := logtest.NewNullLogger()
	w := httptest.NewRecorder()
	logging.NewLoggerHandler("downstream", &logging.Logger{Logger: downstreamLogger}, http.HandlerFunc(api.Sign)).ServeHTTP(w, request)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var native api.SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &native))
	require.NoError(t, native.ServerPEM.CheckSignatureFrom(issuer))
	assert.Equal(t, root.NotAfter, native.ServerPEM.NotAfter)
	assert.Equal(t, hook.LastEntry().Data["certificate-warnings"], native.Warnings)
	require.Len(t, downstreamHook.AllEntries(), 1)
	assert.Equal(t, native.Warnings, downstreamHook.LastEntry().Data["certificate-warnings"])

	old, err := ra.CreateCertificate(&apiv1.CreateCertificateRequest{CSR: testCR, Template: template, Lifetime: 30 * time.Minute})
	require.NoError(t, err)
	assert.Empty(t, old.Warnings)
	shortTemplate := *issuer
	shortTemplate.RawSubject = nil
	shortTemplate.Subject = pkix.Name{CommonName: "Replacement upstream issuer"}
	shortTemplate.SerialNumber = big.NewInt(2)
	shortTemplate.NotAfter = now.Add(15 * time.Minute)
	der, err = x509.CreateCertificate(rand.Reader, &shortTemplate, issuer, testIssKey.Public(), testIssKey)
	require.NoError(t, err)
	shortIssuer, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	chain = []*x509.Certificate{shortIssuer, issuer}
	claims := jose.Claims{ID: uuid.NewString(), Issuer: "step-ca-client/1.0", Subject: old.Certificate.Subject.CommonName, Audience: []string{server.URL + "/renew"}, NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Minute))}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: testKey}, new(jose.SignerOptions).WithType("JWT").WithHeader("x5cInsecure", []string{base64.StdEncoding.EncodeToString(old.Certificate.Raw), base64.StdEncoding.EncodeToString(issuer.Raw)}))
	require.NoError(t, err)
	renewToken, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	renewed, err := ra.RenewCertificate(&apiv1.RenewCertificateRequest{Token: renewToken})
	require.NoError(t, err)
	require.NoError(t, renewed.Certificate.CheckSignatureFrom(shortIssuer))
	assert.Equal(t, shortIssuer.NotAfter, renewed.Certificate.NotAfter)
	assert.Equal(t, old.Certificate.PublicKey, renewed.Certificate.PublicKey)
	require.Len(t, renewed.Warnings, 1)
	assert.Equal(t, hook.LastEntry().Data["certificate-warnings"], renewed.Warnings)
	fingerprint = sha256.Sum256(shortIssuer.Raw)
	assert.Equal(t, hex.EncodeToString(fingerprint[:]), renewed.Warnings[0].LimitingCertificate.Fingerprint)
}
