package kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/cloudkms"
	"github.com/smallstep/certificates/kms/softkms"
	"github.com/smallstep/certificates/kms/yubikey"
)

// KeyManager is the interface implemented by all the KMS.
type KeyManager interface {
	GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error)
	CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error)
	CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error)
	Close() error
}

// CertificateManager is the interface implemented by the KMS that can load and store x509.Certificates.
type CertificateManager interface {
	LoadCerticate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error)
	StoreCertificate(req *apiv1.StoreCertificateRequest) error
}

// New initializes a new KMS from the given type.
func New(ctx context.Context, opts apiv1.Options) (KeyManager, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	switch apiv1.Type(strings.ToLower(opts.Type)) {
	case apiv1.DefaultKMS, apiv1.SoftKMS:
		return softkms.New(ctx, opts)
	case apiv1.CloudKMS:
		return cloudkms.New(ctx, opts)
	case apiv1.YubiKey:
		return yubikey.New(ctx, opts)
	default:
		return nil, errors.Errorf("unsupported kms type '%s'", opts.Type)
	}
}
