package scep

import (
	"context"
	"crypto"
	"crypto/x509"
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
