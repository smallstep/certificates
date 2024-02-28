package userid

import "context"

type userIDKey struct{}

// NewContext returns a new context with the given user ID added to the
// context.
// TODO(hs): this doesn't seem to be used / set currently; implement
// when/where it makes sense.
func NewContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// FromContext returns the user ID from the context if it exists
// and is not empty.
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(userIDKey{}).(string)
	return v, ok && v != ""
}
