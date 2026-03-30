package est

import "context"

// AuthMethod describes the authentication method used for an EST request.
type AuthMethod string

const (
	AuthMethodTLSClientCertificate         AuthMethod = "tls-client-certificate"
	AuthMethodTLSExternalClientCertificate AuthMethod = "tls-external-client-certificate"
	AuthMethodHTTPBasicAuth                AuthMethod = "http-basic-auth"
)

type authMethodKey struct{}

// NewAuthMethodContext stores the EST authentication method in the context.
func NewAuthMethodContext(ctx context.Context, method AuthMethod) context.Context {
	if method == "" {
		return ctx
	}
	return context.WithValue(ctx, authMethodKey{}, method)
}

// AuthMethodFromContext returns the EST authentication method stored in the context.
func AuthMethodFromContext(ctx context.Context) (AuthMethod, bool) {
	method, ok := ctx.Value(authMethodKey{}).(AuthMethod)
	return method, ok
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
