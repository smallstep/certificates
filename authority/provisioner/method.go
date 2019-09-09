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
	// SignSSHMethod is the method used to sign SSH certificate.
	SignSSHMethod
	// RevokeMethod is the method used to revoke X.509 certificates.
	RevokeMethod
)

// NewContextWithMethod creates a new context from ctx and attaches method to
// it.
func NewContextWithMethod(ctx context.Context, method Method) context.Context {
	return context.WithValue(ctx, methodKey{}, method)
}

// MethodFromContext returns the Method saved in ctx. Returns Sign if the given
// context has no Method associated with it.
func MethodFromContext(ctx context.Context) Method {
	m, _ := ctx.Value(methodKey{}).(Method)
	return m
}
