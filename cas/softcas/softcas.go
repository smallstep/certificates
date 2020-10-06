package softcas

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/x509util"
)

func init() {
	apiv1.Register(apiv1.SoftCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

var now = func() time.Time {
	return time.Now()
}

// SoftCAS implements a Certificate Authority Service using Golang or KMS
// crypto. This is the default CAS used in step-ca.
type SoftCAS struct {
	Issuer *x509.Certificate
	Signer crypto.Signer
}

// New creates a new CertificateAuthorityService implementation using Golang or KMS
// crypto.
func New(ctx context.Context, opts apiv1.Options) (*SoftCAS, error) {
	switch {
	case opts.Issuer == nil:
		return nil, errors.New("softCAS 'issuer' cannot be nil")
	case opts.Signer == nil:
		return nil, errors.New("softCAS 'signer' cannot be nil")
	}
	return &SoftCAS{
		Issuer: opts.Issuer,
		Signer: opts.Signer,
	}, nil
}

// CreateCertificate signs a new certificate using Golang or KMS crypto.
func (c *SoftCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("createCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateRequest `lifetime` cannot be 0")
	}

	t := now()
	// Provisioners can also set specific values.
	if req.Template.NotBefore.IsZero() {
		req.Template.NotBefore = t.Add(-1 * req.Backdate)
	}
	if req.Template.NotAfter.IsZero() {
		req.Template.NotAfter = t.Add(req.Lifetime)
	}
	req.Template.Issuer = c.Issuer.Subject

	cert, err := x509util.CreateCertificate(req.Template, c.Issuer, req.Template.PublicKey, c.Signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate: cert,
		CertificateChain: []*x509.Certificate{
			c.Issuer,
		},
	}, nil
}

// RenewCertificate signs the given certificate template using Golang or KMS crypto.
func (c *SoftCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("createCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateRequest `lifetime` cannot be 0")
	}

	t := now()
	req.Template.NotBefore = t.Add(-1 * req.Backdate)
	req.Template.NotAfter = t.Add(req.Lifetime)
	req.Template.Issuer = c.Issuer.Subject

	cert, err := x509util.CreateCertificate(req.Template, c.Issuer, req.Template.PublicKey, c.Signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.RenewCertificateResponse{
		Certificate: cert,
		CertificateChain: []*x509.Certificate{
			c.Issuer,
		},
	}, nil
}

// RevokeCertificate revokes the given certificate in step-ca. In SoftCAS this
// operation is a no-op as the actual revoke will happen when we store the entry
// in the db.
func (c *SoftCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return &apiv1.RevokeCertificateResponse{
		Certificate: req.Certificate,
		CertificateChain: []*x509.Certificate{
			c.Issuer,
		},
	}, nil
}
