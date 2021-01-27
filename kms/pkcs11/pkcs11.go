// +build cgo

package pkcs11

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
)

// DefaultRSASize is the number of bits of a new RSA key if not bitsize has been
// specified.
const DefaultRSASize = 3072

// PKCS11 is the implementation of a KMS using the PKCS #11 standard.
type PKCS11 struct {
	context *crypto11.Context
}

// New returns a new PKCS11 KMS.
func New(ctx context.Context, opts apiv1.Options) (*PKCS11, error) {
	var config crypto11.Config
	if opts.URI != "" {
		u, err := uri.ParseWithScheme("pkcs11", opts.URI)
		if err != nil {
			return nil, err
		}
		config.Path = u.Get("module-path")
		config.TokenLabel = u.Get("token")
		config.TokenSerial = u.Get("serial")
		config.Pin = u.Pin()
	}
	if config.Pin == "" && opts.Pin != "" {
		config.Pin = opts.Pin
	}

	switch {
	case config.Path == "":
		return nil, errors.New("kms uri 'module-path' are required")
	case config.TokenLabel == "" && config.TokenSerial == "":
		return nil, errors.New("kms uri 'token' or 'serial' are required")
	case config.Pin == "":
		return nil, errors.New("kms 'pin' cannot be empty")
	case config.TokenLabel != "" && config.TokenSerial != "":
		return nil, errors.New("kms uri 'token' or 'serial' are mutually exclusive")
	}

	p11Ctx, err := crypto11.Configure(&config)
	if err != nil {
		return nil, errors.Wrap(err, "error initializing PKCS#11")
	}

	return &PKCS11{
		context: p11Ctx,
	}, nil
}

func init() {
	apiv1.Register(apiv1.PKCS11, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// GetPublicKey returns the public key ....
func (k *PKCS11) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	signer, err := findSigner(k.context, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "getPublicKey failed")
	}

	return signer.Public(), nil
}

// CreateKey generates a new key in the PKCS#11 module and returns the public key.
func (k *PKCS11) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	switch {
	case req.Name == "":
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	case req.Bits < 0:
		return nil, errors.New("createKeyRequest 'bits' cannot be negative")
	}

	signer, err := generateKey(k.context, req)
	if err != nil {
		return nil, errors.Wrap(err, "createKey failed")
	}

	return &apiv1.CreateKeyResponse{
		Name:      req.Name,
		PublicKey: signer.Public(),
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: req.Name,
		},
	}, nil
}

// CreateSigner creates a signer using the key present in the PKCS#11 MODULE signature
// slot.
func (k *PKCS11) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	switch {
	case req.SigningKey == "":
		return nil, errors.New("createSignerRequest 'signingKey' cannot be empty")
	}

	signer, err := findSigner(k.context, req.SigningKey)
	if err != nil {
		return nil, errors.Wrap(err, "createSigner failed")
	}

	return signer, nil
}

// LoadCertificate implements kms.CertificateManager and loads a certificate
// from the YubiKey.
func (k *PKCS11) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateRequest 'name' cannot be nil")
	}
	cert, err := findCertificate(k.context, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "loadCertificate failed")
	}
	return cert, nil
}

// StoreCertificate implements kms.CertificateManager and stores a certificate
// in the YubiKey.
func (k *PKCS11) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	switch {
	case req.Name == "":
		return errors.New("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return errors.New("storeCertificateRequest 'Certificate' cannot be nil")
	}

	id, object, err := parseObject(req.Name)
	if err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}

	if err := k.context.ImportCertificateWithLabel(id, object, req.Certificate); err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}

	return nil
}

// DeleteKey is a utility function to delete a key given an uri.
func (k *PKCS11) DeleteKey(uri string) error {
	id, object, err := parseObject(uri)
	if err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	signer, err := k.context.FindKeyPair(id, object)
	if err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	if signer == nil {
		return nil
	}
	if err := signer.Delete(); err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	return nil
}

// DeleteCertificate is a utility function to delete a certificate given an uri.
func (k *PKCS11) DeleteCertificate(uri string) error {
	id, object, err := parseObject(uri)
	if err != nil {
		return errors.Wrap(err, "deleteCertificate failed")
	}
	if err := k.context.DeleteCertificate(id, object, nil); err != nil {
		return errors.Wrap(err, "deleteCertificate failed")
	}
	return nil
}

// Close releases the connection to the PKCS#11 module.
func (k *PKCS11) Close() error {
	return errors.Wrap(k.context.Close(), "error closing pkcs#11 context")
}

func toByte(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func generateKey(ctx *crypto11.Context, req *apiv1.CreateKeyRequest) (crypto11.Signer, error) {
	id, object, err := parseObject(req.Name)
	if err != nil {
		return nil, err
	}
	signer, err := ctx.FindKeyPair(id, object)
	if err != nil {
		return nil, err
	}
	if signer != nil {
		return nil, errors.Errorf("%s already exists", req.Name)
	}

	bits := req.Bits
	if bits == 0 {
		bits = DefaultRSASize
	}

	switch req.SignatureAlgorithm {
	case apiv1.UnspecifiedSignAlgorithm:
		return ctx.GenerateECDSAKeyPairWithLabel(id, object, elliptic.P256())
	case apiv1.SHA256WithRSA, apiv1.SHA384WithRSA, apiv1.SHA512WithRSA:
		return ctx.GenerateRSAKeyPairWithLabel(id, object, bits)
	case apiv1.SHA256WithRSAPSS, apiv1.SHA384WithRSAPSS, apiv1.SHA512WithRSAPSS:
		return ctx.GenerateRSAKeyPairWithLabel(id, object, bits)
	case apiv1.ECDSAWithSHA256:
		return ctx.GenerateECDSAKeyPairWithLabel(id, object, elliptic.P256())
	case apiv1.ECDSAWithSHA384:
		return ctx.GenerateECDSAKeyPairWithLabel(id, object, elliptic.P384())
	case apiv1.ECDSAWithSHA512:
		return ctx.GenerateECDSAKeyPairWithLabel(id, object, elliptic.P521())
	case apiv1.PureEd25519:
		return nil, fmt.Errorf("signature algorithm %s is not supported", req.SignatureAlgorithm)
	default:
		return nil, fmt.Errorf("signature algorithm %s is not supported", req.SignatureAlgorithm)
	}
}

func parseObject(rawuri string) ([]byte, []byte, error) {
	u, err := uri.ParseWithScheme("pkcs11", rawuri)
	if err != nil {
		return nil, nil, err
	}
	id, err := u.GetHex("id")
	if err != nil {
		return nil, nil, err
	}
	object := u.Get("object")
	if len(id) == 0 && object == "" {
		return nil, nil, errors.Errorf("key with uri %s is not valid, id or object are required", rawuri)
	}

	return id, toByte(object), nil
}

func findSigner(ctx *crypto11.Context, rawuri string) (crypto11.Signer, error) {
	id, object, err := parseObject(rawuri)
	if err != nil {
		return nil, err
	}
	signer, err := ctx.FindKeyPair(id, object)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding key with uri %s", rawuri)
	}
	if signer == nil {
		return nil, errors.Errorf("key with uri %s not found", rawuri)
	}
	return signer, nil
}

func findCertificate(ctx *crypto11.Context, rawuri string) (*x509.Certificate, error) {
	u, err := uri.ParseWithScheme("pkcs11", rawuri)
	if err != nil {
		return nil, err
	}
	id, err := u.GetHex("id")
	if err != nil {
		return nil, err
	}
	object, serial := u.Get("object"), u.Get("serial")
	if len(id) == 0 && object == "" && serial == "" {
		return nil, errors.Errorf("key with uri %s is not valid, id, object or serial are required", rawuri)
	}

	var serialNumber *big.Int
	if serial != "" {
		b, err := hex.DecodeString(serial)
		if err != nil {
			return nil, errors.Errorf("key with uri %s is not valid, failed to decode serial", rawuri)
		}
		serialNumber = new(big.Int).SetBytes(b)
	}

	cert, err := ctx.FindCertificate(id, toByte(object), serialNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding certificate with uri %s", rawuri)
	}
	if cert == nil {
		return nil, errors.Errorf("certificate with uri %s not found", rawuri)
	}
	return cert, nil
}
