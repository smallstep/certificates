// +build !cgo

package yubikey

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
)

// YubiKey implements the KMS interface on a YubiKey.
type YubiKey struct{}

// New always fails without CGO.
func New(ctx context.Context, opts apiv1.Options) (*YubiKey, error) {
	return nil, errors.New("YubiKey is not supported without cgo")
}

// LoadCertificate always fails without CGO.
func (k *YubiKey) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	return nil, errors.New("YubiKey is not supported without cgo")
}

// StoreCertificate always fails without CGO.
func (k *YubiKey) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	return errors.New("YubiKey is not supported without cgo")
}

// GetPublicKey always fails without CGO.
func (k *YubiKey) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	return nil, errors.New("YubiKey is not supported without cgo")
}

// CreateKey always fails without CGO.
func (k *YubiKey) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, errors.New("YubiKey is not supported without cgo")
}

// CreateSigner always fails without CGO.
func (k *YubiKey) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	return nil, errors.New("YubiKey is not supported without cgo")
}

// Close always fails without CGO.
func (k *YubiKey) Close() error {
	return errors.New("YubiKey is not supported without cgo")
}
