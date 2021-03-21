package apiv1

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// ProtectionLevel specifies on some KMS how cryptographic operations are
// performed.
type ProtectionLevel int

const (
	// Protection level not specified.
	UnspecifiedProtectionLevel ProtectionLevel = iota
	// Crypto operations are performed in software.
	Software
	// Crypto operations are performed in a Hardware Security Module.
	HSM
)

// String returns a string representation of p.
func (p ProtectionLevel) String() string {
	switch p {
	case UnspecifiedProtectionLevel:
		return "unspecified"
	case Software:
		return "software"
	case HSM:
		return "hsm"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// SignatureAlgorithm used for cryptographic signing.
type SignatureAlgorithm int

const (
	// Not specified.
	UnspecifiedSignAlgorithm SignatureAlgorithm = iota
	// RSASSA-PKCS1-v1_5 key and a SHA256 digest.
	SHA256WithRSA
	// RSASSA-PKCS1-v1_5 key and a SHA384 digest.
	SHA384WithRSA
	// RSASSA-PKCS1-v1_5 key and a SHA512 digest.
	SHA512WithRSA
	// RSASSA-PSS key with a SHA256 digest.
	SHA256WithRSAPSS
	// RSASSA-PSS key with a SHA384 digest.
	SHA384WithRSAPSS
	// RSASSA-PSS key with a SHA512 digest.
	SHA512WithRSAPSS
	// ECDSA on the NIST P-256 curve with a SHA256 digest.
	ECDSAWithSHA256
	// ECDSA on the NIST P-384 curve with a SHA384 digest.
	ECDSAWithSHA384
	// ECDSA on the NIST P-521 curve with a SHA512 digest.
	ECDSAWithSHA512
	// EdDSA on Curve25519 with a SHA512 digest.
	PureEd25519
)

// String returns a string representation of s.
func (s SignatureAlgorithm) String() string {
	switch s {
	case UnspecifiedSignAlgorithm:
		return "unspecified"
	case SHA256WithRSA:
		return "SHA256-RSA"
	case SHA384WithRSA:
		return "SHA384-RSA"
	case SHA512WithRSA:
		return "SHA512-RSA"
	case SHA256WithRSAPSS:
		return "SHA256-RSAPSS"
	case SHA384WithRSAPSS:
		return "SHA384-RSAPSS"
	case SHA512WithRSAPSS:
		return "SHA512-RSAPSS"
	case ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case ECDSAWithSHA512:
		return "ECDSA-SHA512"
	case PureEd25519:
		return "Ed25519"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// GetPublicKeyRequest is the parameter used in the kms.GetPublicKey method.
type GetPublicKeyRequest struct {
	Name string
}

// CreateKeyRequest is the parameter used in the kms.CreateKey method.
type CreateKeyRequest struct {
	// Name represents the key name or label used to identify a key.
	//
	// Used by: awskms, cloudkms, pkcs11, yubikey.
	Name string

	// SignatureAlgorithm represents the type of key to create.
	SignatureAlgorithm SignatureAlgorithm

	// Bits is the number of bits on RSA keys.
	Bits int

	// ProtectionLevel specifies how cryptographic operations are performed.
	// Used by: cloudkms
	ProtectionLevel ProtectionLevel
}

// CreateKeyResponse is the response value of the kms.CreateKey method.
type CreateKeyResponse struct {
	Name                string
	PublicKey           crypto.PublicKey
	PrivateKey          crypto.PrivateKey
	CreateSignerRequest CreateSignerRequest
}

// CreateSignerRequest is the parameter used in the kms.CreateSigner method.
type CreateSignerRequest struct {
	Signer        crypto.Signer
	SigningKey    string
	SigningKeyPEM []byte
	TokenLabel    string
	PublicKey     string
	PublicKeyPEM  []byte
	Password      []byte
}

// CreateDecrypterRequest is the parameter used in the kms.Decrypt method.
type CreateDecrypterRequest struct {
	Decrypter        crypto.Decrypter
	DecryptionKey    string
	DecryptionKeyPEM []byte
	Password         []byte
}

// LoadCertificateRequest is the parameter used in the LoadCertificate method of
// a CertificateManager.
type LoadCertificateRequest struct {
	Name string
}

// StoreCertificateRequest is the parameter used in the StoreCertificate method
// of a CertificateManager.
type StoreCertificateRequest struct {
	Name        string
	Certificate *x509.Certificate
}
