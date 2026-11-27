package logging

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/softcas"
)

func TestCertificateWarnings(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	service, err := softcas.New(context.Background(), apiv1.Options{CertificateChain: []*x509.Certificate{ca.Intermediate}, RootCertificates: []*x509.Certificate{ca.Root}, Signer: ca.Signer})
	require.NoError(t, err)
	issue := func(t *testing.T) *apiv1.CreateCertificateResponse {
		t.Helper()
		response, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{
			Template: &x509.Certificate{Subject: pkix.Name{CommonName: "warning.example"}, PublicKey: ca.Signer.Public(), KeyUsage: x509.KeyUsageDigitalSignature},
			Lifetime: 20 * 365 * 24 * time.Hour,
		})
		require.NoError(t, err)
		require.NoError(t, response.Certificate.CheckSignatureFrom(ca.Intermediate))
		require.Len(t, response.Warnings, 1)
		assert.Equal(t, response.Certificate.NotAfter, response.Warnings[0].EffectiveNotAfter)
		return response
	}

	for _, status := range []int{http.StatusCreated, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			handler := NewLoggerHandler("test", &Logger{Logger: logger}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := issue(t)
				for _, warning := range response.Warnings {
					LogCertificateWarning(r.Context(), warning)
				}
				w.WriteHeader(status)
				_, err := w.Write(response.Certificate.Raw)
				require.NoError(t, err)
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sign", http.NoBody))
			leaf, err := x509.ParseCertificate(w.Body.Bytes())
			require.NoError(t, err)
			require.NoError(t, leaf.CheckSignatureFrom(ca.Intermediate))
			require.Len(t, hook.AllEntries(), 1)
			entry := hook.LastEntry()
			warnings, ok := entry.Data["certificate-warnings"].([]apiv1.CertificateWarning)
			require.True(t, ok)
			require.Len(t, warnings, 1)
			assert.Equal(t, leaf.NotAfter, warnings[0].EffectiveNotAfter)
			if status >= http.StatusInternalServerError {
				assert.Equal(t, logrus.ErrorLevel, entry.Level)
			} else {
				assert.Equal(t, logrus.WarnLevel, entry.Level)
			}
		})
	}

	t.Run("fallback quotes untrusted metadata", func(t *testing.T) {
		response := issue(t)
		warning := response.Warnings[0]
		warning.Message += "\nforged record\r\x1b[31m\u2028\u2029"
		warning.Code += "\n\x00\x1b"
		var output bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&output)
		t.Cleanup(func() { log.SetOutput(previous) })
		LogCertificateWarning(context.Background(), warning)
		assert.Equal(t, 1, strings.Count(output.String(), "\n"))
		assert.Equal(t, 1, strings.Count(output.String(), "WARNING:"))
		assert.NotContains(t, output.String(), "\r")
		assert.NotContains(t, output.String(), "\x1b")
		assert.NotContains(t, output.String(), "\x00")
		assert.NotContains(t, output.String(), "\u2028")
		assert.NotContains(t, output.String(), "\u2029")
		assert.Contains(t, output.String(), `\nforged record\r\x1b[31m`)
	})
}
