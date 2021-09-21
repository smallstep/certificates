//go:build !cgo
// +build !cgo

package pkcs11

import (
	"context"
	"crypto"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
)

var errUnsupported error

func init() {
	name := filepath.Base(os.Args[0])
	errUnsupported = errors.Errorf("unsupported kms type 'pkcs11': %s is compiled without cgo support", name)

	apiv1.Register(apiv1.PKCS11, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return nil, errUnsupported
	})
}

// PKCS11 is the implementation of a KMS using the PKCS #11 standard.
type PKCS11 struct{}

// New implements the kms.KeyManager interface and without CGO will always
// return an error.
func New(ctx context.Context, opts apiv1.Options) (*PKCS11, error) {
	return nil, errUnsupported
}

// GetPublicKey implements the kms.KeyManager interface and without CGO will always
// return an error.
func (*PKCS11) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	return nil, errUnsupported
}

// CreateKey implements the kms.KeyManager interface and without CGO will always
// return an error.
func (*PKCS11) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, errUnsupported
}

// CreateSigner implements the kms.KeyManager interface and without CGO will always
// return an error.
func (*PKCS11) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	return nil, errUnsupported
}

// Close implements the kms.KeyManager interface and without CGO will always
// return an error.
func (*PKCS11) Close() error {
	return errUnsupported
}
