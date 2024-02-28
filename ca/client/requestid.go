package client

import "context"

type requestIDKey struct{}

// WithRequestID returns a new context with the given requestID added to the
// context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// GetRequestID returns the request id from the context if it exists.
func GetRequestID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(requestIDKey{}).(string)
	return v, ok
}
