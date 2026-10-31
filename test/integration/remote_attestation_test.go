package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/attestation"
	cstest "github.com/smallstep/certificates/attestation/confidentialspace/confidentialspacetest"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/webhook"
)

// oidTestAttestation is the OID of the extension the test template sets from
// the verified attestation, under the enterprise number RFC 5612 reserves for
// documentation.
var oidTestAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}

// remoteAttestationTestTemplate names the certificate from the enriching
// webhook's response and records the verified attestation, as a workload
// identity deployment would. The order names nothing itself.
const remoteAttestationTestTemplate = `{
	"subject": {},
	"uris": [{{ toJson .Webhooks.control.spiffeID }}],
	"extensions": [{
		"id": "1.3.6.1.4.1.32473.1",
		"value": {{ asn1Enc (printf "utf8:%s/%s" .Attestation.Format .Attestation.ConfidentialSpace.Claims.hwmodel) | toJson }}
	}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["clientAuth"]
}`

// TestRemoteAttestation runs the ACME remote-attest-01 flow
// (draft-ietf-acme-rats) against a CA, from a new account to the certificate,
// with a Confidential Space token as the evidence and an enriching webhook that
// receives the verified attestation and names the certificate.
func TestRemoteAttestation(t *testing.T) {
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

	// The enriching webhook, served with a certificate from the CA's own
	// PKI, which the CA's webhook client trusts.
	var (
		mu       sync.Mutex
		received *webhook.Attestation
	)
	whSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body webhook.RequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = body.Attestation
		mu.Unlock()
		resp := webhook.ResponseBody{Allow: body.Attestation != nil}
		if body.Attestation != nil {
			resp.Data = map[string]any{"spiffeID": "spiffe://example.org/workload/" + body.Attestation.Hint}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	whKey, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	whCert, err := m.Sign(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		PublicKey:   whKey.Public(),
	})
	require.NoError(t, err)
	whSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{whCert.Raw, m.Intermediate.Raw},
			PrivateKey:  whKey,
		}},
		MinVersion: tls.VersionTLS12,
	}
	whSrv.StartTLS()
	t.Cleanup(whSrv.Close)

	attestor := cstest.New(t)
	host, port := reservePort(t)
	cfg := &config.Config{
		Root:             []string{rootFilepath},
		IntermediateCert: intermediateCertFilepath,
		IntermediateKey:  intermediateKeyFilepath,
		Address:          net.JoinHostPort(host, port),
		DNSNames:         []string{"127.0.0.1", "[::1]", "localhost"},
		AuthorityConfig: &config.AuthConfig{
			AuthorityID:    "stepca-test",
			DeploymentType: "standalone-test",
			Provisioners: provisioner.List{
				&provisioner.ACME{
					Type:       "ACME",
					Name:       "attested",
					Challenges: []provisioner.ACMEChallenge{provisioner.REMOTE_ATTEST_01},
					RemoteAttestation: &provisioner.ACMERemoteAttestation{
						Formats:    []attestation.Format{attestation.FormatConfidentialSpace},
						ClaimsHint: []string{"hwmodel", "submods"},
						ConfidentialSpace: &provisioner.ACMEConfidentialSpace{
							Roots: attestor.RootPEM(),
						},
					},
					Claims: &config.GlobalProvisionerClaims,
					Options: &provisioner.Options{
						X509: &provisioner.X509Options{Template: remoteAttestationTestTemplate},
						Webhooks: []*provisioner.Webhook{{
							Name:     "control",
							URL:      whSrv.URL + "/enrich",
							Kind:     "ENRICHING",
							CertType: "X509",
							Secret:   base64.StdEncoding.EncodeToString([]byte("webhook-secret")),
						}},
					},
				},
			},
		},
		DB: &db.Config{
			Type:       "bbolt",
			DataSource: filepath.Join(dir, "db"),
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := ca.New(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Go(func() {
		err := c.Run()
		require.ErrorIs(t, err, http.ErrServerClosed)
	})
	t.Cleanup(func() {
		require.NoError(t, c.Stop())
		wg.Wait()
	})
	requireCAServerToBeAvailable(t, net.JoinHostPort("localhost", port), 10*time.Second)

	directory := fmt.Sprintf("https://localhost:%s/acme/attested/directory", port)
	client, err := ca.NewACMEClient(directory, nil, ca.WithRootFile(rootFilepath))
	require.NoError(t, err)

	order, err := client.NewOrder([]byte(`{"identifiers":[{"type":"remote-attestation","value":"measured_boot"}]}`))
	require.NoError(t, err)
	require.Len(t, order.AuthorizationURLs, 1)
	az, err := client.GetAuthz(order.AuthorizationURLs[0])
	require.NoError(t, err)
	require.Len(t, az.Challenges, 1)
	ch := az.Challenges[0]
	require.Equal(t, acme.REMOTEATTEST01, ch.Type)
	require.NotEmpty(t, ch.FreshnessNonce)
	assert.Equal(t, []string{"hwmodel", "submods"}, ch.AttestClaimsHint)

	// The workload's key, and the binding its evidence carries first:
	// SHA-256 of the key authorization followed by the key's DER
	// SubjectPublicKeyInfo. The relying party's own nonce follows.
	certKey, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	keyAuth, err := acme.KeyAuthorization(ch.FreshnessNonce, client.Key)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(certKey.Public())
	require.NoError(t, err)
	binding := sha256.Sum256(append([]byte(keyAuth), spki...))
	token := attestor.Mint(t, cstest.Claims(time.Now(), directory,
		base64.RawURLEncoding.EncodeToString(binding[:]),
		"relying-party-nonce",
	))
	payload, err := json.Marshal([]any{"application/eat+jwt", base64.RawURLEncoding.EncodeToString([]byte(token)), 8})
	require.NoError(t, err)
	require.NoError(t, client.ValidateWithPayload(ch.URL, payload))

	ch, err = client.GetChallenge(ch.URL)
	require.NoError(t, err)
	require.Equal(t, acme.StatusValid, ch.Status, "challenge error: %v", ch.Error)

	// A CSR with a key other than the attested one is refused, and the order
	// stays ready.
	otherKey, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	otherDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	require.NoError(t, err)
	otherCSR, err := x509.ParseCertificateRequest(otherDER)
	require.NoError(t, err)
	err = client.FinalizeOrder(order.FinalizeURL, otherCSR)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "The client lacks sufficient authorization")
	readyOrder, err := client.GetOrder(order.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusReady, readyOrder.Status)

	// The order names nothing, so neither does the CSR.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, certKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, client.FinalizeOrder(order.FinalizeURL, csr))
	order, err = client.GetOrder(order.ID)
	require.NoError(t, err)
	require.Equal(t, acme.StatusValid, order.Status)
	leaf, _, err := client.GetCertificate(order.CertificateURL)
	require.NoError(t, err)

	// The webhook received the verified attestation and named the
	// certificate; the template recorded the attestation.
	mu.Lock()
	got := received
	mu.Unlock()
	require.NotNil(t, got)
	assert.Equal(t, "remote-attest-01", got.Challenge)
	assert.Equal(t, "measured_boot", got.Hint)
	assert.Equal(t, ch.FreshnessNonce, got.FreshnessNonce)
	assert.Equal(t, keyAuth, got.KeyAuthorization)
	assert.Equal(t, fmt.Sprintf("%x", binding), got.BindingDigest)
	assert.Empty(t, got.ClaimNonce)
	require.NotNil(t, got.Account)
	assert.NotEmpty(t, got.Account.ID)
	assert.Empty(t, got.Account.Reference)
	assert.Equal(t, []any{base64.RawURLEncoding.EncodeToString(binding[:]), "relying-party-nonce"}, got.ConfidentialSpace.Claims["eat_nonce"])
	assert.Equal(t, attestation.FormatConfidentialSpace, got.Format)
	assert.Equal(t, []byte(token), got.Evidence)
	require.NotNil(t, got.ConfidentialSpace)
	assert.Equal(t, "my-project", got.ConfidentialSpace.Claims["submods"].(map[string]any)["gce"].(map[string]any)["project_id"])

	spiffeID, err := url.Parse("spiffe://example.org/workload/measured_boot")
	require.NoError(t, err)
	assert.Equal(t, []*url.URL{spiffeID}, leaf.URIs)
	assert.Empty(t, leaf.DNSNames)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, leaf.ExtKeyUsage)
	var recorded string
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidTestAttestation) {
			_, err := asn1.UnmarshalWithParams(ext.Value, &recorded, "utf8")
			require.NoError(t, err)
		}
	}
	assert.Equal(t, "confidential-space/GCP_INTEL_TDX", recorded)
}
