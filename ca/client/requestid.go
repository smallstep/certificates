package client

import "context"

type contextKey struct{}

// NewRequestIDContext returns a new context with the given request ID added to the
// context.
func NewRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, contextKey{}, requestID)
}

// RequestIDFromContext returns the request ID from the context if it exists.
// and is not empty.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(contextKey{}).(string)
	return v, ok && v != ""
}
