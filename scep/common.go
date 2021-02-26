package scep

import (
	"context"
	"errors"

	"github.com/smallstep/certificates/acme"
)

// ProvisionerFromContext searches the context for a SCEP provisioner.
// Returns the provisioner or an error.
func ProvisionerFromContext(ctx context.Context) (Provisioner, error) {
	val := ctx.Value(acme.ProvisionerContextKey)
	if val == nil {
		return nil, errors.New("provisioner expected in request context")
	}
	p, ok := val.(Provisioner)
	if !ok || p == nil {
		return nil, errors.New("provisioner in context is not a SCEP provisioner")
	}
	return p, nil
}
