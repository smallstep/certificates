package scep

import (
	"context"
	"errors"
)

// ContextKey is the key type for storing and searching for SCEP request
// essentials in the context of a request.
type ContextKey string

const (
	// ProvisionerContextKey provisioner key
	ProvisionerContextKey = ContextKey("provisioner")
)

// provisionerFromContext searches the context for a SCEP provisioner.
// Returns the provisioner or an error.
func provisionerFromContext(ctx context.Context) (Provisioner, error) {
	val := ctx.Value(ProvisionerContextKey)
	if val == nil {
		return nil, errors.New("provisioner expected in request context")
	}
	p, ok := val.(Provisioner)
	if !ok || p == nil {
		return nil, errors.New("provisioner in context is not a SCEP provisioner")
	}
	return p, nil
}
