package softcas

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/cas/apiv1"
)

func init() {
	apiv1.Register(apiv1.SoftCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

var now = time.Now

// SoftCAS implements a Certificate Authority Service using Golang or KMS
// crypto. This is the default CAS used in step-ca.
type SoftCAS struct {
	CertificateChain  []*x509.Certificate
	Signer            crypto.Signer
	CertificateSigner func() ([]*x509.Certificate, crypto.Signer, error)
	KeyManager        kms.KeyManager
}

// New creates a new CertificateAuthorityService implementation using Golang or KMS
// crypto.
func New(_ context.Context, opts apiv1.Options) (*SoftCAS, error) {
	if !opts.IsCreator {
		switch {
		case len(opts.CertificateChain) == 0 && opts.CertificateSigner == nil:
			return nil, errors.New("softCAS 'CertificateChain' cannot be nil")
		case opts.Signer == nil && opts.CertificateSigner == nil:
			return nil, errors.New("softCAS 'signer' cannot be nil")
		}
	}
	return &SoftCAS{
		CertificateChain:  opts.CertificateChain,
		Signer:            opts.Signer,
		CertificateSigner: opts.CertificateSigner,
		KeyManager:        opts.KeyManager,
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

	chain, signer, err := c.getCertSigner()
	if err != nil {
		return nil, err
	}
	req.Template.Issuer = chain[0].Subject

	cert, err := createCertificate(req.Template, chain[0], req.Template.PublicKey, signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
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

	chain, signer, err := c.getCertSigner()
	if err != nil {
		return nil, err
	}
	req.Template.Issuer = chain[0].Subject

	cert, err := createCertificate(req.Template, chain[0], req.Template.PublicKey, signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

// RevokeCertificate revokes the given certificate in step-ca. In SoftCAS this
// operation is a no-op as the actual revoke will happen when we store the entry
// in the db.
func (c *SoftCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	chain, _, err := c.getCertSigner()
	if err != nil {
		return nil, err
	}
	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: chain,
	}, nil
}

// CreateCRL will create a new CRL based on the RevocationList passed to it
func (c *SoftCAS) CreateCRL(req *apiv1.CreateCRLRequest) (*apiv1.CreateCRLResponse, error) {
	certChain, signer, err := c.getCertSigner()
	if err != nil {
		return nil, err
	}
	revocationListBytes, err := x509.CreateRevocationList(rand.Reader, req.RevocationList, certChain[0], signer)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCRLResponse{CRL: revocationListBytes}, nil
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
		cert, err = createCertificate(req.Template, req.Template, signer.Public(), signer)
		if err != nil {
			return nil, err
		}
	case apiv1.IntermediateCA:
		cert, err = createCertificate(req.Template, req.Parent.Certificate, signer.Public(), req.Parent.Signer)
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
		KeyName:          key.Name,
		PublicKey:        key.PublicKey,
		PrivateKey:       key.PrivateKey,
		Signer:           signer,
	}, nil
}

// initializeKeyManager initializes the default key manager if was not given.
func (c *SoftCAS) initializeKeyManager() (err error) {
	if c.KeyManager == nil {
		c.KeyManager, err = kms.New(context.Background(), kmsapi.Options{
			Type: kmsapi.DefaultKMS,
		})
	}
	return
}

// getCertSigner returns the certificate chain and signer to use.
func (c *SoftCAS) getCertSigner() ([]*x509.Certificate, crypto.Signer, error) {
	if c.CertificateSigner != nil {
		return c.CertificateSigner()
	}
	return c.CertificateChain, c.Signer, nil
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

// createCertificate sets the SignatureAlgorithm of the template if necessary
// and calls x509util.CreateCertificate.
func createCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	// Signers can specify the signature algorithm. This is especially important
	// when x509.CreateCertificate attempts to validate a RSAPSS signature.
	if template.SignatureAlgorithm == 0 {
		if sa, ok := signer.(apiv1.SignatureAlgorithmGetter); ok {
			template.SignatureAlgorithm = sa.SignatureAlgorithm()
		} else if _, ok := parent.PublicKey.(*rsa.PublicKey); ok {
			// For RSA issuers, only overwrite the default algorithm is the
			// intermediate is signed with an RSA signature scheme.
			if isRSA(parent.SignatureAlgorithm) {
				template.SignatureAlgorithm = parent.SignatureAlgorithm
			}
		}
	}
	return x509util.CreateCertificate(template, parent, pub, signer)
}

func isRSA(sa x509.SignatureAlgorithm) bool {
	switch sa {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return true
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}
