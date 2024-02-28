package logging

import (
	"context"
)

type userIDKey struct{}

// WithUserID decodes the token, extracts the user from the payload and stores
// it in the context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// GetUserID returns the request id from the context if it exists.
func GetUserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(userIDKey{}).(string)
	return v, ok && v != ""
}
