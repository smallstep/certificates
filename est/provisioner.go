package est

import (
	"context"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/authority/provisioner/est"
)

// Provisioner is an interface that embeds the generic provisioner.Interface and
// adds EST-specific helpers.
type Provisioner interface {
	provisioner.Interface
	GetOptions() *provisioner.Options
	GetClientCertificateConfig() *provisioner.ClientCertificateConfig
	AuthorizeRequest(ctx context.Context, req est.AuthRequest) ([]provisioner.SignCSROption, error)
	GetCSRAttributes(ctx context.Context) ([]byte, error)
}

// provisionerKey is the key type for storing and searching an EST provisioner in the context.
type provisionerKey struct{}

// provisionerFromContext searches the context for an EST provisioner.
// Returns the provisioner or panics if no EST provisioner is found.
func provisionerFromContext(ctx context.Context) Provisioner {
	p, ok := ctx.Value(provisionerKey{}).(Provisioner)
	if !ok {
		panic("EST provisioner expected in request context")
	}
	return p
}

// NewProvisionerContext returns a new context with the EST provisioner set.
func NewProvisionerContext(ctx context.Context, p Provisioner) context.Context {
	return context.WithValue(ctx, provisionerKey{}, p)
}

// ProvisionerFromContext returns the EST provisioner stored in the context.
func ProvisionerFromContext(ctx context.Context) Provisioner {
	return provisionerFromContext(ctx)
}
