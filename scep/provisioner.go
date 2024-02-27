package scep

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Provisioner is an interface that embeds the
// provisioner.Interface and adds some SCEP specific
// functions.
type Provisioner interface {
	provisioner.Interface
	GetOptions() *provisioner.Options
	GetCapabilities() []string
	ShouldIncludeRootInChain() bool
	ShouldIncludeIntermediateInChain() bool
	GetDecrypter() (*x509.Certificate, crypto.Decrypter)
	GetSigner() (*x509.Certificate, crypto.Signer)
	GetContentEncryptionAlgorithm() int
	ValidateChallenge(ctx context.Context, csr *x509.CertificateRequest, challenge, transactionID string) error
	NotifySuccess(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, transactionID string) error
	NotifyFailure(ctx context.Context, csr *x509.CertificateRequest, transactionID string, errorCode int, errorDescription string) error
}

// provisionerKey is the key type for storing and searching a
// SCEP provisioner in the context.
type provisionerKey struct{}

// provisionerFromContext searches the context for a SCEP provisioner.
// Returns the provisioner or panics if no SCEP provisioner is found.
func provisionerFromContext(ctx context.Context) Provisioner {
	p, ok := ctx.Value(provisionerKey{}).(Provisioner)
	if !ok {
		panic("SCEP provisioner expected in request context")
	}
	return p
}

func NewProvisionerContext(ctx context.Context, p Provisioner) context.Context {
	return context.WithValue(ctx, provisionerKey{}, p)
}
