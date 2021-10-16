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

// Decrypter is an interface implemented by KMSes that are used
// in operations that require decryption
type Decrypter interface {
	CreateDecrypter(req *CreateDecrypterRequest) (crypto.Decrypter, error)
}

// CertificateManager is the interface implemented by the KMS that can load and
// store x509.Certificates.
type CertificateManager interface {
	LoadCertificate(req *LoadCertificateRequest) (*x509.Certificate, error)
	StoreCertificate(req *StoreCertificateRequest) error
}

// ValidateName is an interface that KeyManager can implement to validate a
// given name or URI.
type NameValidator interface {
	ValidateName(s string) error
}

// ErrNotImplemented is the type of error returned if an operation is not
// implemented.
type ErrNotImplemented struct {
	Message string
}

func (e ErrNotImplemented) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "not implemented"
}

// ErrAlreadyExists is the type of error returned if a key already exists. This
// is currently only implmented on pkcs11.
type ErrAlreadyExists struct {
	Message string
}

func (e ErrAlreadyExists) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "key already exists"
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
	// SSHAgentKMS is a KMS implementation using ssh-agent to access keys.
	SSHAgentKMS Type = "sshagentkms"
	// AzureKMS is a KMS implementation using Azure Key Vault.
	AzureKMS Type = "azurekms"
)

// Options are the KMS options. They represent the kms object in the ca.json.
type Options struct {
	// The type of the KMS to use.
	Type string `json:"type"`

	// Path to the credentials file used in CloudKMS and AmazonKMS.
	CredentialsFile string `json:"credentialsFile,omitempty"`

	// URI is based on the PKCS #11 URI Scheme defined in
	// https://tools.ietf.org/html/rfc7512 and represents the configuration used
	// to connect to the KMS.
	//
	// Used by: pkcs11
	URI string `json:"uri,omitempty"`

	// Pin used to access the PKCS11 module. It can be defined in the URI using
	// the pin-value or pin-source properties.
	Pin string `json:"pin,omitempty"`

	// ManagementKey used in YubiKeys. Default management key is the hexadecimal
	// string 010203040506070801020304050607080102030405060708:
	//   []byte{
	//       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	//       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	//       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	//   }
	ManagementKey string `json:"managementKey,omitempty"`

	// Region to use in AmazonKMS.
	Region string `json:"region,omitempty"`

	// Profile to use in AmazonKMS.
	Profile string `json:"profile,omitempty"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}

	switch Type(strings.ToLower(o.Type)) {
	case DefaultKMS, SoftKMS: // Go crypto based kms.
	case CloudKMS, AmazonKMS, AzureKMS: // Cloud based kms.
	case YubiKey, PKCS11: // Hardware based kms.
	case SSHAgentKMS: // Others
	default:
		return errors.Errorf("unsupported kms type %s", o.Type)
	}

	return nil
}
