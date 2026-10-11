package api

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/pkcs7"
	smallscep "github.com/smallstep/scep"
	scepx509util "github.com/smallstep/scep/x509util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/middleware/requestid"
	"github.com/smallstep/certificates/scep"
	"github.com/smallstep/certificates/webhook"
)

type issuerValiditySigner struct {
	crypto.Signer
	calls int
	fail  bool
}

func (s *issuerValiditySigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if s.fail {
		return nil, errors.New("private signer unavailable")
	}
	return s.Signer.Sign(random, digest, opts)
}

func issuerValidityCA(t *testing.T, now, limit time.Time) *minica.CA {
	t.Helper()
	ca, err := minica.New(minica.WithGetSignerFunc(func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	}))
	require.NoError(t, err)
	root := *ca.Root
	root.NotBefore, root.NotAfter = now.Add(-time.Hour), limit
	ca.Root, err = x509util.CreateCertificate(&root, &root, ca.RootSigner.Public(), ca.RootSigner)
	require.NoError(t, err)
	intermediate := *ca.Intermediate
	intermediate.NotBefore, intermediate.NotAfter = now.Add(-time.Hour), now.Add(96*time.Hour)
	ca.Intermediate, err = x509util.CreateCertificate(&intermediate, ca.Root, ca.Signer.Public(), ca.RootSigner)
	require.NoError(t, err)
	require.NoError(t, ca.Intermediate.CheckSignatureFrom(ca.Root))
	return ca
}

func TestIssuerValidityLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      casapi.IssuerValidityLimit
		requested time.Duration
		remaining time.Duration
		fail      bool
		warning   bool
		reason    string
		fallback  bool
	}{
		{"default truncates", "", 72 * time.Hour, 36 * time.Hour, false, true, "", false},
		{"explicit truncate", casapi.IssuerValidityLimitTruncate, 72 * time.Hour, 36 * time.Hour, false, true, "", false},
		{"below minimum remains usable", "", 72 * time.Hour, time.Minute, false, true, "", false},
		{"without logger warns through fallback", "", 72 * time.Hour, 36 * time.Hour, false, true, "", true},
		{"equal expiry stays silent", "", 36 * time.Hour, 36 * time.Hour, false, false, "", false},
		{"earlier expiry stays silent", "", time.Hour, 36 * time.Hour, false, false, "", false},
		{"reject overrun", casapi.IssuerValidityLimitReject, 72 * time.Hour, 36 * time.Hour, false, false, "exceeds_limit", false},
		{"reject permits earlier expiry", casapi.IssuerValidityLimitReject, time.Hour, 36 * time.Hour, false, false, "", false},
		{"expired root rejects", "", 72 * time.Hour, -time.Minute, false, false, "no_remaining_validity", false},
		{"signer error stays internal", "", 72 * time.Hour, 36 * time.Hour, true, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			limit, requested := now.Add(tc.remaining), now.Add(tc.requested)
			ca := issuerValidityCA(t, now, limit)
			signer := &issuerValiditySigner{Signer: ca.Signer, fail: tc.fail}
			type notificationResult struct {
				body webhook.RequestBody
				err  error
			}
			notifications := make(chan notificationResult, 2)
			notifyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body webhook.RequestBody
				err := json.NewDecoder(r.Body).Decode(&body)
				notifications <- notificationResult{body, err}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"allow":true}`)
			}))
			t.Cleanup(notifyServer.Close)
			prov := &provisioner.SCEP{
				Type: "SCEP", Name: "issuer-validity", ChallengePassword: "test-challenge",
				EncryptionAlgorithmIdentifier: pkcs7.EncryptionAlgorithmAES256CBC,
				Claims:                        &provisioner.Claims{MaxTLSDur: &provisioner.Duration{Duration: 96 * time.Hour}},
				Options: &provisioner.Options{
					X509: &provisioner.X509Options{Template: fmt.Sprintf(`{
						"subject": {{ toJson .Subject }}, "sans": {{ toJson .SANs }},
						"keyUsage": ["digitalSignature", "keyEncipherment"],
						"extKeyUsage": ["serverAuth", "clientAuth"],
						"notBefore": %q, "notAfter": %q
					}`, now.Format(time.RFC3339), requested.Format(time.RFC3339))},
					Webhooks: []*provisioner.Webhook{{
						ID: "notify", Name: "notify", Kind: "NOTIFYING", CertType: "X509",
						URL: notifyServer.URL, Secret: "dGVzdC1zZWNyZXQ=",
					}},
				},
			}
			a, err := authority.NewEmbedded(
				authority.WithConfig(&config.Config{
					DB: &db.Config{Type: "bbolt", DataSource: filepath.Join(t.TempDir(), "ca.db")},
					AuthorityConfig: &config.AuthConfig{
						Options:      &casapi.Options{IssuerValidityLimit: tc.mode},
						Provisioners: provisioner.List{prov},
					},
				}),
				authority.WithX509RootCerts(ca.Root),
				authority.WithX509Signer(ca.Intermediate, signer),
				authority.WithFullSCEPOptions(&scep.Options{
					Roots: []*x509.Certificate{ca.Root}, Intermediates: []*x509.Certificate{ca.Intermediate},
					SignerCert: ca.Intermediate, Signer: ca.Signer,
					DecrypterCert: ca.Intermediate, Decrypter: ca.Signer.(*rsa.PrivateKey),
				}),
				authority.WithQuietInit(),
				authority.WithWebhookClient(notifyServer.Client()),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, a.Shutdown()) })
			msg, clientCert, clientKey := issuerValidityRequest(t, ca.Intermediate, now)
			router := chi.NewRouter()
			Route(router)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := authority.NewContext(r.Context(), a)
				ctx = scep.NewContext(ctx, a.GetSCEP())
				router.ServeHTTP(w, r.WithContext(ctx))
			})
			logger, err := logging.New("scep", json.RawMessage(`{"format":"json"}`))
			require.NoError(t, err)
			var logs bytes.Buffer
			logger.SetOutput(&logs)
			handler := requestid.New("").Middleware(logger.Middleware(next))
			if tc.fallback {
				handler = next
				previous := stdlog.Writer()
				stdlog.SetOutput(&logs)
				t.Cleanup(func() { stdlog.SetOutput(previous) })
			}
			req := httptest.NewRequest(http.MethodPost, "https://ca.local/issuer-validity?operation=PKIOperation", bytes.NewReader(msg.Raw))
			req.Header.Set("Content-Type", "application/x-pki-message")
			req.Header.Set("X-Request-Id", tc.name)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, "application/x-pki-message", w.Header().Get("Content-Type"))
			reply, err := smallscep.ParsePKIMessage(w.Body.Bytes(), smallscep.WithCACerts([]*x509.Certificate{ca.Intermediate}))
			require.NoError(t, err, "standard SCEP clients can verify the unextended CertRep")
			assert.Equal(t, smallscep.CertRep, reply.MessageType)
			assert.Equal(t, msg.TransactionID, reply.TransactionID)
			assert.Equal(t, smallscep.RecipientNonce(msg.SenderNonce), reply.RecipientNonce)
			signed, err := pkcs7.Parse(w.Body.Bytes())
			require.NoError(t, err)
			require.NoError(t, signed.Verify())
			require.NotNil(t, signed.GetOnlySigner())
			assert.Equal(t, ca.Intermediate.Raw, signed.GetOnlySigner().Raw)

			var record map[string]json.RawMessage
			if !tc.fallback {
				decoder := json.NewDecoder(&logs)
				require.NoError(t, decoder.Decode(&record))
				var extra map[string]json.RawMessage
				require.ErrorIs(t, decoder.Decode(&extra), io.EOF, "one structured access log per issuance")
				assert.JSONEq(t, fmt.Sprintf("%q", tc.name), string(record["request-id"]))
				assert.JSONEq(t, `200`, string(record["status"]))
			}
			var notified notificationResult
			select {
			case notified = <-notifications:
			default:
				t.Fatal("SCEP success/failure notification was not delivered")
			}
			require.NoError(t, notified.err)
			assert.Equal(t, string(msg.TransactionID), notified.body.SCEPTransactionID)
			select {
			case <-notifications:
				t.Fatal("duplicate SCEP notification")
			default:
			}
			failInfoTextOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 24, 1}
			var failInfoText string
			if tc.reason != "" || tc.fail {
				assert.Equal(t, smallscep.FAILURE, reply.PKIStatus)
				assert.Equal(t, smallscep.BadRequest, reply.FailInfo)
				require.NoError(t, signed.UnmarshalSignedAttribute(failInfoTextOID, &failInfoText))
				assert.Nil(t, notified.body.X509Certificate, "failure notification must not report issued material")
				assert.Empty(t, signed.Content, "failure CertRep does not contain an issued certificate")
				assert.NotContains(t, record, "certificate-warnings")
				assert.JSONEq(t, `"info"`, string(record["level"]), "SCEP failure envelope retains HTTP 200 logging behavior")
				if tc.reason != "" {
					assert.Zero(t, signer.calls, "policy rejection happens before private signing")
					// Independently spell the expected policy text instead of
					// re-running the production formatter, so a formatter
					// regression that drops a timestamp cannot pass unnoticed.
					var wantText string
					switch tc.reason {
					case "exceeds_limit":
						wantText = fmt.Sprintf("requested certificate expiration %s exceeds issuing CA chain expiration %s",
							requested.UTC().Truncate(time.Second).Format(time.RFC3339), limit.UTC().Truncate(time.Second).Format(time.RFC3339))
					case "no_remaining_validity":
						wantText = fmt.Sprintf("issuing CA chain expiration %s leaves no usable certificate validity; contact the CA operator",
							limit.UTC().Truncate(time.Second).Format(time.RFC3339))
					}
					assert.Equal(t, wantText, failInfoText)
					assert.Contains(t, notified.body.SCEPErrorDescription, wantText, "NotifyFailure is preserved")
				} else {
					assert.Equal(t, 1, signer.calls)
					assert.Equal(t, "internal server error; please see the certificate authority logs for more info", failInfoText)
					assert.Contains(t, notified.body.SCEPErrorDescription, "private signer unavailable")
					assert.NotContains(t, failInfoText, "private signer unavailable")
				}
				return
			}

			assert.Equal(t, smallscep.SUCCESS, reply.PKIStatus)
			assert.Empty(t, reply.FailInfo)
			assert.Error(t, signed.UnmarshalSignedAttribute(failInfoTextOID, &failInfoText))
			envelope, err := pkcs7.Parse(signed.Content)
			require.NoError(t, err)
			content, err := envelope.Decrypt(clientCert, clientKey)
			require.NoError(t, err)
			certificates, err := pkcs7.Parse(content)
			require.NoError(t, err)
			require.Len(t, certificates.Certificates, 1, "successful SCEP payload remains a leaf-only certificate bag")
			leaf := certificates.Certificates[0]
			expectedExpiry := requested
			if tc.warning {
				expectedExpiry = limit
			}
			assert.Equal(t, expectedExpiry, leaf.NotAfter)
			assert.Equal(t, now, leaf.NotBefore)
			assert.Equal(t, []string{"leaf.example"}, leaf.DNSNames)
			assert.Equal(t, clientKey.Public(), leaf.PublicKey)
			require.NoError(t, leaf.CheckSignatureFrom(ca.Intermediate))
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(ca.Root)
			intermediates.AddCert(ca.Intermediate)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "leaf.example", CurrentTime: now})
			require.NoError(t, err)
			stored, err := a.GetDatabase().GetCertificate(leaf.SerialNumber.String())
			require.NoError(t, err)
			assert.Equal(t, leaf.Raw, stored.Raw)
			require.NotNil(t, notified.body.X509Certificate)
			assert.Equal(t, leaf.Raw, notified.body.X509Certificate.Raw)
			assert.Empty(t, notified.body.SCEPErrorDescription)
			switch {
			case tc.fallback:
				assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("WARNING:")))
				assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("\n")))
				assert.Contains(t, logs.String(), "issuer_validity_truncated")
				assert.Contains(t, logs.String(), limit.Format(time.RFC3339))
			case tc.warning:
				assert.JSONEq(t, `"warning"`, string(record["level"]))
				var warnings []casapi.CertificateWarning
				require.NoError(t, json.Unmarshal(record["certificate-warnings"], &warnings))
				require.Len(t, warnings, 1)
				assert.Equal(t, "issuer_validity_truncated", warnings[0].Code)
				assert.Equal(t, requested, warnings[0].RequestedNotAfter)
				assert.Equal(t, limit, warnings[0].EffectiveNotAfter)
				hash := sha256.Sum256(ca.Root.Raw)
				assert.Equal(t, casapi.LimitingCertificate{Subject: ca.Root.Subject.String(), Fingerprint: hex.EncodeToString(hash[:]), NotAfter: limit}, warnings[0].LimitingCertificate)
			default:
				assert.JSONEq(t, `"info"`, string(record["level"]))
				assert.NotContains(t, record, "certificate-warnings")
			}
		})
	}
}

func issuerValidityRequest(t *testing.T, recipient *x509.Certificate, now time.Time) (*smallscep.PKIMessage, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("leaf.example", []string{"leaf.example"}, key)
	require.NoError(t, err)
	der, err := scepx509util.CreateCertificateRequest(rand.Reader, &scepx509util.CertificateRequest{
		CertificateRequest: *csr, ChallengePassword: "test-challenge",
	}, key)
	require.NoError(t, err)
	csr, err = x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	template := &x509.Certificate{
		Subject: csr.Subject, PublicKey: key.Public(), SerialNumber: big.NewInt(1),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	cert, err := x509util.CreateCertificate(template, template, key.Public(), key)
	require.NoError(t, err)
	msg, err := smallscep.NewCSRRequest(csr, &smallscep.PKIMessage{
		TransactionID: "issuer-validity", MessageType: smallscep.PKCSReq, SenderNonce: []byte("test-nonce-12345"),
		Recipients: []*x509.Certificate{recipient}, SignerCert: cert, SignerKey: key,
	})
	require.NoError(t, err)
	return msg, cert, key
}
