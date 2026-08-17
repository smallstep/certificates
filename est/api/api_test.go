package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
