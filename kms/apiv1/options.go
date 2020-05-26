package apiv1

import (
	"crypto"
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
)

// KeyManager is the interface implemented by all the KMS.
type KeyManager interface {
	GetPublicKey(req *GetPublicKeyRequest) (crypto.PublicKey, error)
	CreateKey(req *CreateKeyRequest) (*CreateKeyResponse, error)
	CreateSigner(req *CreateSignerRequest) (crypto.Signer, error)
	Close() error
}

// CertificateManager is the interface implemented by the KMS that can load and
// store x509.Certificates.
type CertificateManager interface {
	LoadCerticate(req *LoadCertificateRequest) (*x509.Certificate, error)
	StoreCertificate(req *StoreCertificateRequest) error
}

// ErrNotImplemented
type ErrNotImplemented struct {
	msg string
}

func (e ErrNotImplemented) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "not implemented"
}

// Type represents the KMS type used.
type Type string

const (
	// DefaultKMS is a KMS implementation using software.
	DefaultKMS Type = ""
	// SoftKMS is a KMS implementation using software.
	SoftKMS Type = "softkms"
	// CloudKMS is a KMS implementation using Google's Cloud KMS.
	CloudKMS Type = "cloudkms"
	// AmazonKMS is a KMS implementation using Amazon AWS KMS.
	AmazonKMS Type = "awskms"
	// PKCS11 is a KMS implementation using the PKCS11 standard.
	PKCS11 Type = "pkcs11"
	// YubiKey is a KMS implementation using a YubiKey PIV.
	YubiKey Type = "yubikey"
)

type Options struct {
	// The type of the KMS to use.
	Type string `json:"type"`

	// Path to the credentials file used in CloudKMS and AmazonKMS.
	CredentialsFile string `json:"credentialsFile"`

	// Path to the module used with PKCS11 KMS.
	Module string `json:"module"`

	// Pin used to access the PKCS11 module.
	Pin string `json:"pin"`

	// Region to use in AmazonKMS.
	Region string `json:"region"`

	// Profile to use in AmazonKMS.
	Profile string `json:"profile"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}

	switch Type(strings.ToLower(o.Type)) {
	case DefaultKMS, SoftKMS, CloudKMS, AmazonKMS:
	case YubiKey:
	case PKCS11:
		return ErrNotImplemented{"support for PKCS11 is not yet implemented"}
	default:
		return errors.Errorf("unsupported kms type %s", o.Type)
	}

	return nil
}
