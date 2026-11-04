package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_writeResponse(t *testing.T) {
	type args struct {
		w           http.ResponseWriter
		r           *http.Request
		data        []byte
		contentType string
		status      int
	}
	tests := []struct {
		name        string
		args        args
		wantBody    string
		wantHeaders map[string]string
	}{
		{
			name: "ok",
			args: args{
				w:           httptest.NewRecorder(),
				r:           httptest.NewRequest("GET", "/", nil),
				data:        []byte("hello world"),
				contentType: "application/pkcs7-mime; smime-type=certs-only",
				status:      http.StatusOK,
			},
			wantBody: base64.StdEncoding.EncodeToString([]byte("hello world")),
			wantHeaders: map[string]string{
				"Content-Type":              "application/pkcs7-mime; smime-type=certs-only",
				"Content-Transfer-Encoding": "base64",
			},
		},
		{
			name: "ok/csrattrs",
			args: args{
				w:           httptest.NewRecorder(),
				r:           httptest.NewRequest("GET", "/", nil),
				data:        []byte("attribute data"),
				contentType: "application/csrattrs",
				status:      http.StatusOK,
			},
			wantBody: base64.StdEncoding.EncodeToString([]byte("attribute data")),
			wantHeaders: map[string]string{
				"Content-Type":              "application/csrattrs",
				"Content-Transfer-Encoding": "base64",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeResponse(tt.args.w, tt.args.data, tt.args.contentType, tt.args.status)
			resp := tt.args.w.(*httptest.ResponseRecorder)

			assert.Equal(t, tt.args.status, resp.Code)
			assert.Equal(t, tt.wantBody, resp.Body.String())

			for k, v := range tt.wantHeaders {
				assert.Equal(t, v, resp.Header().Get(k))
			}
		})
	}
}

func Test_parseForwardedClientCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mustCert := func(serial int64) []byte {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		require.NoError(t, err)
		return der
	}
	leaf, intermediate := base64.StdEncoding.EncodeToString(mustCert(1)), base64.StdEncoding.EncodeToString(mustCert(2))

	tests := []struct {
		name       string
		value      string
		wantSerial []int64
		wantErr    bool
	}{
		{name: "single certificate", value: leaf, wantSerial: []int64{1}},
		{name: "traefik comma separated chain keeps the leaf first", value: leaf + "," + intermediate, wantSerial: []int64{1, 2}},
		{name: "url escaped chain", value: url.QueryEscape(leaf + "," + intermediate), wantSerial: []int64{1, 2}},
		{name: "invalid base64", value: "not base64!", wantErr: true},
		{name: "invalid escape", value: "%zz", wantErr: true},
		{name: "not a certificate", value: base64.StdEncoding.EncodeToString([]byte("nope")), wantErr: true},
		{name: "empty", value: ",", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseForwardedClientCertificates(tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, certs, len(tt.wantSerial))
			for i, serial := range tt.wantSerial {
				require.Equal(t, serial, certs[i].SerialNumber.Int64())
			}
		})
	}
}
