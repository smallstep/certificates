package cas

import (
	"context"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"

	// Enable default implementation
	_ "github.com/smallstep/certificates/cas/softcas"
)

// CertificateAuthorityService is the interface implemented by all the CAS.
type CertificateAuthorityService = apiv1.CertificateAuthorityService

// CertificateAuthorityCreator is the interface implemented by all CAS that can create a new authority.
type CertificateAuthorityCreator = apiv1.CertificateAuthorityCreator

// New creates a new CertificateAuthorityService using the given options.
func New(ctx context.Context, opts apiv1.Options) (CertificateAuthorityService, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	t := apiv1.Type(strings.ToLower(opts.Type))
	if t == apiv1.DefaultCAS {
		t = apiv1.SoftCAS
	}

	fn, ok := apiv1.LoadCertificateAuthorityServiceNewFunc(t)
	if !ok {
		return nil, errors.Errorf("unsupported cas type '%s'", t)
	}
	return fn(ctx, opts)
}

// NewCreator creates a new CertificateAuthorityCreator using the given options.
func NewCreator(ctx context.Context, opts apiv1.Options) (CertificateAuthorityCreator, error) {
	opts.IsCreator = true

	t := apiv1.Type(strings.ToLower(opts.Type))
	if t == apiv1.DefaultCAS {
		t = apiv1.SoftCAS
	}

	svc, err := New(ctx, opts)
	if err != nil {
		return nil, err
	}

	creator, ok := svc.(CertificateAuthorityCreator)
	if !ok {
		return nil, errors.Errorf("cas type '%s' does not implements CertificateAuthorityCreator", t)
	}

	return creator, nil
}
