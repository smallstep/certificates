package provisioner

import (
	"context"
)

// Method indicates the action to action that we will perform, it's used as part
// of the context in the call to authorize. It defaults to Sing.
type Method int

// The key to save the Method in the context.
type methodKey struct{}

const (
	// SignMethod is the method used to sign X.509 certificates.
	SignMethod Method = iota
	// SignIdentityMethod is the method used to sign X.509 identity certificates.
	SignIdentityMethod
	// RevokeMethod is the method used to revoke X.509 certificates.
	RevokeMethod
	// RenewMethod is the method used to renew X.509 certificates.
	RenewMethod
	// SSHSignMethod is the method used to sign SSH certificates.
	SSHSignMethod
	// SSHRenewMethod is the method used to renew SSH certificates.
	SSHRenewMethod
	// SSHRevokeMethod is the method used to revoke SSH certificates.
	SSHRevokeMethod
	// SSHRekeyMethod is the method used to rekey SSH certificates.
	SSHRekeyMethod
)

// String returns a string representation of the context method.
func (m Method) String() string {
	switch m {
	case SignMethod:
		return "sign-method"
	case SignIdentityMethod:
		return "sign-identity-method"
	case RevokeMethod:
		return "revoke-method"
	case RenewMethod:
		return "renew-method"
	case SSHSignMethod:
		return "ssh-sign-method"
	case SSHRenewMethod:
		return "ssh-renew-method"
	case SSHRevokeMethod:
		return "ssh-revoke-method"
	case SSHRekeyMethod:
		return "ssh-rekey-method"
	default:
		return "unknown"
	}
}

// NewContextWithMethod creates a new context from ctx and attaches method to
// it.
func NewContextWithMethod(ctx context.Context, method Method) context.Context {
	return context.WithValue(ctx, methodKey{}, method)
}

// MethodFromContext returns the Method saved in ctx.
func MethodFromContext(ctx context.Context) Method {
	m, _ := ctx.Value(methodKey{}).(Method)
	return m
}

type tokenKey struct{}

// NewContextWithToken creates a new context with the given token.
func NewContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

// TokenFromContext returns the token stored in the given context.
func TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenKey{}).(string)
	return token, ok
}
