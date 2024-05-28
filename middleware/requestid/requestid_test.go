package requestid

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	require.NoError(t, err)
	return r
}

func Test_Middleware(t *testing.T) {
	requestWithID := newRequest(t)
	requestWithID.Header.Set("X-Request-Id", "reqID")

	requestWithoutID := newRequest(t)

	requestWithEmptyHeader := newRequest(t)
	requestWithEmptyHeader.Header.Set("X-Request-Id", "")

	requestWithSmallstepID := newRequest(t)
	requestWithSmallstepID.Header.Set("X-Smallstep-Id", "smallstepID")

	tests := []struct {
		name        string
		traceHeader string
		next        http.HandlerFunc
		req         *http.Request
	}{
		{
			name:        "default-request-id",
			traceHeader: defaultTraceHeader,
			next: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Smallstep-Id"))
				assert.Equal(t, "reqID", r.Header.Get("X-Request-Id"))
				reqID, ok := FromContext(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, "reqID", reqID)
				}
				assert.Equal(t, "reqID", w.Header().Get("X-Request-Id"))
			},
			req: requestWithID,
		},
		{
			name:        "no-request-id",
			traceHeader: "X-Request-Id",
			next: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Smallstep-Id"))
				value := r.Header.Get("X-Request-Id")
				assert.NotEmpty(t, value)
				reqID, ok := FromContext(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, value, reqID)
				}
				assert.Equal(t, value, w.Header().Get("X-Request-Id"))
			},
			req: requestWithoutID,
		},
		{
			name:        "empty-header",
			traceHeader: "",
			next: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Request-Id"))
				value := r.Header.Get("X-Smallstep-Id")
				assert.NotEmpty(t, value)
				reqID, ok := FromContext(r.Context())
				if assert.True(t, ok) {
					assert.Equal(t, value, reqID)
				}
				assert.Equal(t, value, w.Header().Get("X-Request-Id"))
			},
			req: requestWithEmptyHeader,
		},
		{
			name:        "fallback-header-name",
			traceHeader: defaultTraceHeader,
			next: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Request-Id"))
				assert.Equal(t, "smallstepID", r.Header.Get("X-Smallstep-Id"))
				reqID, ok := FromContext(r.Context())
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
			handler := New(tt.traceHeader).Middleware(tt.next)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, tt.req)
			assert.NotEmpty(t, w.Header().Get("X-Request-Id"))
		})
	}
}
