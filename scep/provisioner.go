package scep

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Provisioner is an interface that implements a subset of the provisioner.Interface --
// only those methods required by the SCEP api/authority.
type Provisioner interface {
	AuthorizeSign(ctx context.Context, token string) ([]provisioner.SignOption, error)
	GetName() string
	DefaultTLSCertDuration() time.Duration
	GetOptions() *provisioner.Options
	GetCapabilities() []string
	ShouldIncludeRootInChain() bool
	GetDecrypter() (*x509.Certificate, crypto.Decrypter)
	GetContentEncryptionAlgorithm() int
	ValidateChallenge(ctx context.Context, challenge, transactionID string) error
}

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
