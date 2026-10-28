package est

import "context"

// AuthenticationHeaderKey is the context key used to store the EST authentication header.
type AuthenticationHeaderKey struct{}

// NewAuthenticationHeaderContext stores the EST authentication header in the context.
func NewAuthenticationHeaderContext(ctx context.Context, header string) context.Context {
	if header == "" {
		return ctx
	}
	return context.WithValue(ctx, AuthenticationHeaderKey{}, header)
}

// AuthenticationHeaderFromContext returns the EST authentication header stored in the context.
func AuthenticationHeaderFromContext(ctx context.Context) (string, bool) {
	header, ok := ctx.Value(AuthenticationHeaderKey{}).(string)
	return header, ok
}

// BasicAuth holds the HTTP basic auth credentials for an EST request.
type BasicAuth struct {
	Username string
	Password string
}

type basicAuthKey struct{}

// NewBasicAuthContext stores the HTTP basic auth credentials in the context.
func NewBasicAuthContext(ctx context.Context, auth BasicAuth) context.Context {
	if auth.Username == "" && auth.Password == "" {
		return ctx
	}
	return context.WithValue(ctx, basicAuthKey{}, auth)
}

// BasicAuthFromContext returns the HTTP basic auth credentials stored in the context.
func BasicAuthFromContext(ctx context.Context) (BasicAuth, bool) {
	auth, ok := ctx.Value(basicAuthKey{}).(BasicAuth)
	return auth, ok
}

type BearerTokenKey struct{}

// NewBearerTokenContext stores the HTTP bearer token in the context.
func NewBearerTokenContext(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, BearerTokenKey{}, token)
}

// BearerTokenFromContext returns the HTTP bearer token stored in the context.
func BearerTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(BearerTokenKey{}).(string)
	return token, ok
}
