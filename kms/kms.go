package kms

import (
	"context"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"

	// Enable default implementation
	_ "github.com/smallstep/certificates/kms/softkms"
)

// KeyManager is the interface implemented by all the KMS.
type KeyManager = apiv1.KeyManager

// CertificateManager is the interface implemented by the KMS that can load and
// store x509.Certificates.
type CertificateManager = apiv1.CertificateManager

// New initializes a new KMS from the given type.
func New(ctx context.Context, opts apiv1.Options) (KeyManager, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	t := apiv1.Type(strings.ToLower(opts.Type))
	if t == apiv1.DefaultKMS {
		t = apiv1.SoftKMS
	}

	fn, ok := apiv1.LoadKeyManagerNewFunc(t)
	if !ok {
		return nil, errors.Errorf("unsupported kms type '%s'", t)
	}
	return fn(ctx, opts)
}
