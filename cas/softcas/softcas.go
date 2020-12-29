package softcas

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/kms"
	kmsapi "github.com/smallstep/certificates/kms/apiv1"
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
	CertificateChain []*x509.Certificate
	Signer           crypto.Signer
	KeyManager       kms.KeyManager
}

// New creates a new CertificateAuthorityService implementation using Golang or KMS
// crypto.
func New(ctx context.Context, opts apiv1.Options) (*SoftCAS, error) {
	if !opts.IsCreator {
		switch {
		case len(opts.CertificateChain) == 0:
			return nil, errors.New("softCAS 'CertificateChain' cannot be nil")
		case opts.Signer == nil:
			return nil, errors.New("softCAS 'signer' cannot be nil")
		}
	}
	return &SoftCAS{
		CertificateChain: opts.CertificateChain,
		Signer:           opts.Signer,
		KeyManager:       opts.KeyManager,
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
	req.Template.Issuer = c.CertificateChain[0].Subject

	cert, err := x509util.CreateCertificate(req.Template, c.CertificateChain[0], req.Template.PublicKey, c.Signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: c.CertificateChain,
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
	req.Template.Issuer = c.CertificateChain[0].Subject

	cert, err := x509util.CreateCertificate(req.Template, c.CertificateChain[0], req.Template.PublicKey, c.Signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: c.CertificateChain,
	}, nil
}

// RevokeCertificate revokes the given certificate in step-ca. In SoftCAS this
// operation is a no-op as the actual revoke will happen when we store the entry
// in the db.
func (c *SoftCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: c.CertificateChain,
	}, nil
}

// CreateCertificateAuthority creates a root or an intermediate certificate.
func (c *SoftCAS) CreateCertificateAuthority(req *apiv1.CreateCertificateAuthorityRequest) (*apiv1.CreateCertificateAuthorityResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("createCertificateAuthorityRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateAuthorityRequest `lifetime` cannot be 0")
	case req.Type == apiv1.IntermediateCA && req.Parent == nil:
		return nil, errors.New("createCertificateAuthorityRequest `parent` cannot be nil")
	case req.Type == apiv1.IntermediateCA && req.Parent.Certificate == nil:
		return nil, errors.New("createCertificateAuthorityRequest `parent.template` cannot be nil")
	case req.Type == apiv1.IntermediateCA && req.Parent.Signer == nil:
		return nil, errors.New("createCertificateAuthorityRequest `parent.signer` cannot be nil")
	}

	key, err := c.createKey(req.CreateKey)
	if err != nil {
		return nil, err
	}

	signer, err := c.createSigner(&key.CreateSignerRequest)
	if err != nil {
		return nil, err
	}

	t := now()
	if req.Template.NotBefore.IsZero() {
		req.Template.NotBefore = t.Add(-1 * req.Backdate)
	}
	if req.Template.NotAfter.IsZero() {
		req.Template.NotAfter = t.Add(req.Lifetime)
	}

	var cert *x509.Certificate
	switch req.Type {
	case apiv1.RootCA:
		cert, err = x509util.CreateCertificate(req.Template, req.Template, signer.Public(), signer)
		if err != nil {
			return nil, err
		}
	case apiv1.IntermediateCA:
		cert, err = x509util.CreateCertificate(req.Template, req.Parent.Certificate, signer.Public(), req.Parent.Signer)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Errorf("createCertificateAuthorityRequest `type=%d' is invalid or not supported", req.Type)
	}

	// Add the parent
	var chain []*x509.Certificate
	if req.Parent != nil {
		chain = append(chain, req.Parent.Certificate)
		chain = append(chain, req.Parent.CertificateChain...)
	}

	return &apiv1.CreateCertificateAuthorityResponse{
		Name:             cert.Subject.CommonName,
		Certificate:      cert,
		CertificateChain: chain,
		PublicKey:        key.PublicKey,
		PrivateKey:       key.PrivateKey,
		Signer:           signer,
	}, nil
}

// initializeKeyManager initiazes the default key manager if was not given.
func (c *SoftCAS) initializeKeyManager() (err error) {
	if c.KeyManager == nil {
		c.KeyManager, err = kms.New(context.Background(), kmsapi.Options{
			Type: string(kmsapi.DefaultKMS),
		})
	}
	return
}

// createKey uses the configured kms to create a key.
func (c *SoftCAS) createKey(req *kmsapi.CreateKeyRequest) (*kmsapi.CreateKeyResponse, error) {
	if err := c.initializeKeyManager(); err != nil {
		return nil, err
	}
	if req == nil {
		req = &kmsapi.CreateKeyRequest{
			SignatureAlgorithm: kmsapi.ECDSAWithSHA256,
		}
	}
	return c.KeyManager.CreateKey(req)
}

// createSigner uses the configured kms to create a singer
func (c *SoftCAS) createSigner(req *kmsapi.CreateSignerRequest) (crypto.Signer, error) {
	if err := c.initializeKeyManager(); err != nil {
		return nil, err
	}
	return c.KeyManager.CreateSigner(req)
}
