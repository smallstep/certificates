package api

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CRL(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: data,
	})
	pemData = bytes.TrimSpace(pemData)
	emptyPEMData := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: nil,
	})
	emptyPEMData = bytes.TrimSpace(emptyPEMData)
	tests := []struct {
		name              string
		url               string
		err               error
		statusCode        int
		crlInfo           *authority.CertificateRevocationListInfo
		expectedBody      []byte
		expectedHeaders   http.Header
		expectedErrorJSON string
	}{
		{"ok", "http://example.com/crl", nil, http.StatusOK, &authority.CertificateRevocationListInfo{Data: data}, data, http.Header{"Content-Type": []string{"application/pkix-crl"}, "Content-Disposition": []string{`attachment; filename="crl.der"`}}, ""},
		{"ok/pem", "http://example.com/crl?pem=true", nil, http.StatusOK, &authority.CertificateRevocationListInfo{Data: data}, pemData, http.Header{"Content-Type": []string{"application/x-pem-file"}, "Content-Disposition": []string{`attachment; filename="crl.pem"`}}, ""},
		{"ok/empty", "http://example.com/crl", nil, http.StatusOK, &authority.CertificateRevocationListInfo{Data: nil}, nil, http.Header{"Content-Type": []string{"application/pkix-crl"}, "Content-Disposition": []string{`attachment; filename="crl.der"`}}, ""},
		{"ok/empty-pem", "http://example.com/crl?pem=true", nil, http.StatusOK, &authority.CertificateRevocationListInfo{Data: nil}, emptyPEMData, http.Header{"Content-Type": []string{"application/x-pem-file"}, "Content-Disposition": []string{`attachment; filename="crl.pem"`}}, ""},
		{"fail/internal", "http://example.com/crl", errs.Wrap(http.StatusInternalServerError, errors.New("failure"), "authority.GetCertificateRevocationList"), http.StatusInternalServerError, nil, nil, http.Header{}, `{"status":500,"message":"The certificate authority encountered an Internal Server Error. Please see the certificate authority logs for more info."}`},
		{"fail/nil", "http://example.com/crl", nil, http.StatusNotFound, nil, nil, http.Header{}, `{"status":404,"message":"no CRL available"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: tt.crlInfo, err: tt.err})

			chiCtx := chi.NewRouteContext()
			req := httptest.NewRequest("GET", tt.url, http.NoBody)
			req = req.WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx))
			w := httptest.NewRecorder()
			CRL(w, req)
			res := w.Result()

			assert.Equal(t, tt.statusCode, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			require.NoError(t, err)

			if tt.statusCode >= 300 {
				assert.JSONEq(t, tt.expectedErrorJSON, string(bytes.TrimSpace(body)))
				return
			}

			// check expected header values
			for _, h := range []string{"content-type", "content-disposition"} {
				v := tt.expectedHeaders.Get(h)
				require.NotEmpty(t, v)

				actual := res.Header.Get(h)
				assert.Equal(t, v, actual)
			}

			// check expires header value
			assert.NotEmpty(t, res.Header.Get("expires"))
			t1, err := time.Parse(time.RFC1123, res.Header.Get("expires"))
			if assert.NoError(t, err) {
				assert.False(t, t1.IsZero())
			}

			// check body contents
			assert.Equal(t, tt.expectedBody, bytes.TrimSpace(body))
		})
	}
}
