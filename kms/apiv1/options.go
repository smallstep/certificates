package apiv1

import (
	"strings"

	"github.com/pkg/errors"
)

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
)

type Options struct {
	// The type of the KMS to use.
	Type string `json:"type"`

	// Path to the credentials file used in CloudKMS.
	CredentialsFile string `json:"credentialsFile"`

	// Path to the module used with PKCS11 KMS.
	Module string `json:"module"`

	// Pin used to access the PKCS11 module.
	Pin string `json:"pin"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}

	switch Type(strings.ToLower(o.Type)) {
	case DefaultKMS, SoftKMS, CloudKMS:
	case AmazonKMS:
		return ErrNotImplemented{"support for AmazonKMS is not yet implemented"}
	case PKCS11:
		return ErrNotImplemented{"support for PKCS11 is not yet implemented"}
	default:
		return errors.Errorf("unsupported kms type %s", o.Type)
	}

	return nil
}
