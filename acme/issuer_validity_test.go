package acme_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/acme"
	acmeapi "github.com/smallstep/certificates/acme/api"
	acmedb "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/middleware/requestid"
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
	ca, err := minica.New()
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

// Exercise the real authenticated ACME router, authority, SoftCAS and database.
// The account and completed authorizations are pre-created so no DNS is required.
func TestIssuerValidityLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      casapi.IssuerValidityLimit
		requested time.Duration
		remaining time.Duration
		fail      bool
		status    int
		warning   bool
		reason    string
		fallback  bool
	}{
		{"default truncates", "", 72 * time.Hour, 36 * time.Hour, false, http.StatusOK, true, "", false},
		{"explicit truncate", casapi.IssuerValidityLimitTruncate, 72 * time.Hour, 36 * time.Hour, false, http.StatusOK, true, "", false},
		{"below minimum remains usable", "", 72 * time.Hour, time.Minute, false, http.StatusOK, true, "", false},
		{"without logger warns through fallback", "", 72 * time.Hour, 36 * time.Hour, false, http.StatusOK, true, "", true},
		{"equal expiry stays silent", "", 36 * time.Hour, 36 * time.Hour, false, http.StatusOK, false, "", false},
		{"earlier expiry stays silent", "", time.Hour, 36 * time.Hour, false, http.StatusOK, false, "", false},
		{"reject overrun", casapi.IssuerValidityLimitReject, 72 * time.Hour, 36 * time.Hour, false, http.StatusBadRequest, false, "exceeds_limit", false},
		{"reject permits earlier expiry", casapi.IssuerValidityLimitReject, time.Hour, 36 * time.Hour, false, http.StatusOK, false, "", false},
		{"expired root rejects", "", 72 * time.Hour, -time.Minute, false, http.StatusBadRequest, false, "no_remaining_validity", false},
		{"signer error remains internal", "", 72 * time.Hour, 36 * time.Hour, true, http.StatusInternalServerError, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			limit, requested := now.Add(tc.remaining), now.Add(tc.requested)
			ca := issuerValidityCA(t, now, limit)
			signer := &issuerValiditySigner{Signer: ca.Signer, fail: tc.fail}
			prov := &provisioner.ACME{Type: "ACME", Name: "issuer-validity", Claims: &provisioner.Claims{
				MaxTLSDur: &provisioner.Duration{Duration: 96 * time.Hour},
			}}
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
				authority.WithQuietInit(),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, a.Shutdown()) })
			store, err := acmedb.New(a.GetDatabase().(*db.DB))
			require.NoError(t, err)
			ctx := context.Background()
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			public := jwk.Public()
			account := &acme.Account{
				Key: &public, Status: acme.StatusValid,
				ProvisionerID: prov.GetID(), ProvisionerName: prov.GetName(),
				LocationPrefix: "https://ca.local/acme/issuer-validity/account/",
			}
			require.NoError(t, store.CreateAccount(ctx, account))
			order := &acme.Order{
				AccountID: account.ID, ProvisionerID: prov.GetID(), Status: acme.StatusReady,
				ExpiresAt: now.Add(time.Hour), NotBefore: now, NotAfter: requested,
				Identifiers: []acme.Identifier{{Type: acme.DNS, Value: "leaf.example"}},
			}
			require.NoError(t, store.CreateOrder(ctx, order))
			key, err := keyutil.GenerateDefaultSigner()
			require.NoError(t, err)
			csr, err := x509util.CreateCertificateRequest("leaf.example", []string{"leaf.example"}, key)
			require.NoError(t, err)
			payload, err := json.Marshal(acmeapi.FinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr.Raw)})
			require.NoError(t, err)

			router := chi.NewRouter()
			router.Route("/acme", func(r chi.Router) {
				acmeapi.NewHandler(acmeapi.HandlerOptions{DB: store, CA: a, DNS: "ca.local", Prefix: "acme"}).Route(r)
			})
			logger, err := logging.New("acme", json.RawMessage(`{"format":"json"}`))
			require.NoError(t, err)
			var logs bytes.Buffer
			logger.SetOutput(&logs)
			handler := requestid.New("").Middleware(logger.Middleware(router))
			if tc.fallback {
				handler = router
				previous := stdlog.Writer()
				stdlog.SetOutput(&logs)
				t.Cleanup(func() { stdlog.SetOutput(previous) })
			}
			url := fmt.Sprintf("https://ca.local/acme/issuer-validity/order/%s/finalize", order.ID)
			req := issuerValidityACMERequest(t, store, jwk, account.GetLocation(), url, payload)
			req.Header.Set("X-Request-Id", tc.name)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.fallback {
				assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("WARNING:")))
				assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("\n")))
				assert.Contains(t, logs.String(), "issuer_validity_truncated")
				assert.Contains(t, logs.String(), limit.Format(time.RFC3339))
			} else {
				var record map[string]json.RawMessage
				decoder := json.NewDecoder(&logs)
				require.NoError(t, decoder.Decode(&record))
				var extra map[string]json.RawMessage
				require.ErrorIs(t, decoder.Decode(&extra), io.EOF, "one access log, not an extra warning line")
				assert.JSONEq(t, fmt.Sprintf("%q", tc.name), string(record["request-id"]))
				if tc.warning {
					assert.JSONEq(t, `"warning"`, string(record["level"]))
					var warnings []casapi.CertificateWarning
					require.NoError(t, json.Unmarshal(record["certificate-warnings"], &warnings))
					require.Len(t, warnings, 1)
					assert.Equal(t, "issuer_validity_truncated", warnings[0].Code)
					assert.Equal(t, requested, warnings[0].RequestedNotAfter)
					assert.Equal(t, limit, warnings[0].EffectiveNotAfter)
					hash := sha256.Sum256(ca.Root.Raw)
					assert.Equal(t, casapi.LimitingCertificate{Subject: ca.Root.Subject.String(), Fingerprint: hex.EncodeToString(hash[:]), NotAfter: limit}, warnings[0].LimitingCertificate)
				} else {
					assert.NotContains(t, record, "certificate-warnings")
					level := "info"
					if tc.status >= 500 {
						level = "error"
					} else if tc.status >= 400 {
						level = "warning"
					}
					assert.JSONEq(t, fmt.Sprintf("%q", level), string(record["level"]))
				}
			}
			storedOrder, err := store.GetOrder(ctx, order.ID)
			require.NoError(t, err)
			if tc.status != http.StatusOK {
				assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))
				var problem acme.Error
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &problem))
				assert.Equal(t, acme.StatusReady, storedOrder.Status)
				assert.Empty(t, storedOrder.CertificateID)
				if tc.reason != "" {
					assert.Zero(t, signer.calls, "policy rejection occurs before private signing")
					assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problem.Type)
					// Independently spell the expected problem detail instead of
					// re-running the production formatter, so a formatter
					// regression that drops a timestamp cannot pass unnoticed.
					var wantDetail string
					switch tc.reason {
					case "exceeds_limit":
						wantDetail = fmt.Sprintf("requested certificate expiration %s exceeds issuing CA chain expiration %s",
							requested.UTC().Truncate(time.Second).Format(time.RFC3339), limit.UTC().Truncate(time.Second).Format(time.RFC3339))
					case "no_remaining_validity":
						wantDetail = fmt.Sprintf("issuing CA chain expiration %s leaves no usable certificate validity; contact the CA operator",
							limit.UTC().Truncate(time.Second).Format(time.RFC3339))
					}
					assert.Equal(t, "The CSR is unacceptable: "+wantDetail, problem.Detail)
				} else {
					assert.Equal(t, 1, signer.calls)
					assert.Equal(t, "urn:ietf:params:acme:error:serverInternal", problem.Type)
					assert.NotContains(t, problem.Detail, "private signer unavailable")
				}
				return
			}

			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fields))
			assert.NotContains(t, fields, "warnings", "ACME does not add native warning extensions")
			assert.Equal(t, acme.StatusValid, storedOrder.Status)
			storedCert, err := store.GetCertificate(ctx, storedOrder.CertificateID)
			require.NoError(t, err)
			expectedExpiry := requested
			if tc.warning {
				expectedExpiry = limit
			}
			assert.Equal(t, expectedExpiry, storedCert.Leaf.NotAfter)
			assert.Equal(t, now, storedCert.Leaf.NotBefore)
			assert.Equal(t, []string{"leaf.example"}, storedCert.Leaf.DNSNames)
			require.NoError(t, storedCert.Leaf.CheckSignatureFrom(ca.Intermediate))
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(ca.Root)
			intermediates.AddCert(ca.Intermediate)
			_, err = storedCert.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "leaf.example", CurrentTime: now})
			require.NoError(t, err)
			downloadURL := fmt.Sprintf("https://ca.local/acme/issuer-validity/certificate/%s", storedOrder.CertificateID)
			download := httptest.NewRecorder()
			// A POST-as-GET carries an explicitly empty payload; nil produces a detached JWS.
			handler.ServeHTTP(download, issuerValidityACMERequest(t, store, jwk, account.GetLocation(), downloadURL, []byte{}))
			require.Equal(t, http.StatusOK, download.Code, download.Body.String())
			assert.Equal(t, "application/pem-certificate-chain", download.Header().Get("Content-Type"))
			block, rest := pem.Decode(download.Body.Bytes())
			require.NotNil(t, block)
			assert.Equal(t, storedCert.Leaf.Raw, block.Bytes)
			block, rest = pem.Decode(rest)
			require.NotNil(t, block)
			assert.Equal(t, ca.Intermediate.Raw, block.Bytes)
			assert.Empty(t, bytes.TrimSpace(rest), "certificate payload contains neither root nor warning metadata")
		})
	}
}

func issuerValidityACMERequest(t *testing.T, store acme.DB, key *jose.JSONWebKey, kid, url string, payload []byte) *http.Request {
	t.Helper()
	nonce, err := store.CreateNonce(context.Background())
	require.NoError(t, err)
	opts := new(jose.SignerOptions)
	opts.WithHeader("kid", kid).WithHeader("nonce", string(nonce)).WithHeader("url", url)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.Key}, opts)
	require.NoError(t, err)
	signed, err := signer.Sign(payload)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(signed.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")
	return req
}
