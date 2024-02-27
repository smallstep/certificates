package logging

import (
	"context"
	"net/http"

	"github.com/rs/xid"
)

type key int

const (
	// RequestIDKey is the context key that should store the request identifier.
	RequestIDKey key = iota
	// UserIDKey is the context key that should store the user identifier.
	UserIDKey
)

// NewRequestID creates a new request id using github.com/rs/xid.
func NewRequestID() string {
	return xid.New().String()
}

// requestIDHeader is the header name used for propagating request IDs. If
// available in an HTTP request, it'll be used instead of the X-Smallstep-Id
// header. It'll always be used in response and set to the request ID.
const requestIDHeader = "X-Request-Id"

// RequestID returns a new middleware that obtains the current request ID
// and sets it in the context. It first tries to read the request ID from
// the "X-Request-Id" header. If that's not set, it tries to read it from
// the provided header name. If the header does not exist or its value is
// the empty string, it uses github.com/rs/xid to create a new one.
func RequestID(headerName string) func(next http.Handler) http.Handler {
	if headerName == "" {
		headerName = defaultTraceIDHeader
	}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, req *http.Request) {
			requestID := req.Header.Get(requestIDHeader)
			if requestID == "" {
				requestID = req.Header.Get(headerName)
			}

			if requestID == "" {
				requestID = NewRequestID()
				req.Header.Set(headerName, requestID)
			}

			// immediately set the request ID to be reflected in the response
			w.Header().Set(requestIDHeader, requestID)

			// continue down the handler chain
			ctx := WithRequestID(req.Context(), requestID)
			next.ServeHTTP(w, req.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// WithRequestID returns a new context with the given requestID added to the
// context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID returns the request id from the context if it exists.
func GetRequestID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(RequestIDKey).(string)
	return v, ok
}

// WithUserID decodes the token, extracts the user from the payload and stores
// it in the context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// GetUserID returns the request id from the context if it exists.
func GetUserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(UserIDKey).(string)
	return v, ok
}
