package logging

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRequest(t *testing.T) *http.Request {
	r, err := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	require.NoError(t, err)
	return r
}

func TestRequestID(t *testing.T) {
	requestWithID := newRequest(t)
	requestWithID.Header.Set("X-Request-Id", "reqID")
	requestWithoutID := newRequest(t)
	requestWithEmptyHeader := newRequest(t)
	requestWithEmptyHeader.Header.Set("X-Request-Id", "")
	requestWithSmallstepID := newRequest(t)
	requestWithSmallstepID.Header.Set("X-Smallstep-Id", "smallstepID")

	tests := []struct {
		name       string
		headerName string
		handler    http.HandlerFunc
		req        *http.Request
	}{
		{
			name:       "default-request-id",
			headerName: defaultTraceIDHeader,
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Smallstep-Id"))
				assert.Equal(t, "reqID", r.Header.Get("X-Request-Id"))
				reqID, ok := GetRequestID(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, "reqID", reqID)
				}
				assert.Equal(t, "reqID", w.Header().Get("X-Request-Id"))
			},
			req: requestWithID,
		},
		{
			name:       "no-request-id",
			headerName: "X-Request-Id",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Smallstep-Id"))
				value := r.Header.Get("X-Request-Id")
				assert.NotEmpty(t, value)
				reqID, ok := GetRequestID(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, value, reqID)
				}
				assert.Equal(t, value, w.Header().Get("X-Request-Id"))
			},
			req: requestWithoutID,
		},
		{
			name:       "empty-header-name",
			headerName: "",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Request-Id"))
				value := r.Header.Get("X-Smallstep-Id")
				assert.NotEmpty(t, value)
				reqID, ok := GetRequestID(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, value, reqID)
				}
				assert.Equal(t, value, w.Header().Get("X-Request-Id"))
			},
			req: requestWithEmptyHeader,
		},
		{
			name:       "fallback-header-name",
			headerName: defaultTraceIDHeader,
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Request-Id"))
				assert.Equal(t, "smallstepID", r.Header.Get("X-Smallstep-Id"))
				reqID, ok := GetRequestID(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, "smallstepID", reqID)
				}
				assert.Equal(t, "smallstepID", w.Header().Get("X-Request-Id"))
			},
			req: requestWithSmallstepID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := RequestID(tt.headerName)
			h(tt.handler).ServeHTTP(httptest.NewRecorder(), tt.req)
		})
	}
}
