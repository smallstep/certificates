package softcas

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/x509util"
)

func init() {
	apiv1.Register(apiv1.SoftCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

// SoftCAS implements a Certificate Authority Service using Golang crypto.
// This is the default CAS used in step-ca.
type SoftCAS struct{}

// New creates a new CertificateAuthorityService implementation using Golang
// crypto.
func New(ctx context.Context, opts apiv1.Options) (*SoftCAS, error) {
	return &SoftCAS{}, nil
}

// CreateCertificate signs a new certificate using Golang crypto.
func (c *SoftCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	cert, err := x509util.CreateCertificate(req.Template, req.Issuer, req.Template.PublicKey, req.Signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate: cert,
		CertificateChain: []*x509.Certificate{
			req.Issuer,
		},
	}, nil
}

func (c *SoftCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

// RevokeCertificate revokes the given certificate in step-ca.
func (c *SoftCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return nil, fmt.Errorf("not implemented")
}
