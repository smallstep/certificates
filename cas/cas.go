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
		return nil, errors.Errorf("unsupported kms type '%s'", t)
	}
	return fn(ctx, opts)
}
