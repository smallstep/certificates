// Package requestid provides HTTP request ID functionality
package requestid

import (
	"context"
	"net/http"

	"github.com/rs/xid"

	"go.step.sm/crypto/randutil"
)

const (
	// requestIDHeader is the header name used for propagating request IDs. If
	// available in an HTTP request, it'll be used instead of the X-Smallstep-Id
	// header. It'll always be used in response and set to the request ID.
	requestIDHeader = "X-Request-Id"

	// defaultTraceHeader is the default Smallstep tracing header that's currently
	// in use. It is used as a fallback to retrieve a request ID from, if the
	// "X-Request-Id" request header is not set.
	defaultTraceHeader = "X-Smallstep-Id"
)

type Handler struct {
	legacyTraceHeader string
}

// New creates a new request ID [handler]. It takes a trace header,
// which is used keep the legacy behavior intact, which relies on the
// X-Smallstep-Id header instead of X-Request-Id.
func New(legacyTraceHeader string) *Handler {
	if legacyTraceHeader == "" {
		legacyTraceHeader = defaultTraceHeader
	}

	return &Handler{legacyTraceHeader: legacyTraceHeader}
}

// Middleware wraps an [http.Handler] with request ID extraction
// from the X-Reqeust-Id header by default, or from the X-Smallstep-Id
// header if not set. If both are not set, a new request ID is generated.
// In all cases, the request ID is added to the request context, and
// set to be reflected in the response.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		requestID := req.Header.Get(requestIDHeader)
		if requestID == "" {
			requestID = req.Header.Get(h.legacyTraceHeader)
		}

		if requestID == "" {
			requestID = newRequestID()
			req.Header.Set(h.legacyTraceHeader, requestID) // legacy behavior
		}

		// immediately set the request ID to be reflected in the response
		w.Header().Set(requestIDHeader, requestID)

		// continue down the handler chain
		ctx := NewContext(req.Context(), requestID)
		next.ServeHTTP(w, req.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

// newRequestID generates a new random UUIDv4 request ID. If UUIDv4
// generation fails, it'll fallback to generating a random ID using
// github.com/rs/xid.
func newRequestID() string {
	requestID, err := randutil.UUIDv4()
	if err != nil {
		requestID = xid.New().String()
	}

	return requestID
}

type contextKey struct{}

// NewContext returns a new context with the given request ID added to the
// context.
func NewContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, contextKey{}, requestID)
}

// FromContext returns the request ID from the context if it exists and
// is not the empty value.
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(contextKey{}).(string)
	return v, ok && v != ""
}
