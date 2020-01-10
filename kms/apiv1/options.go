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
	SoftKMS = "softkms"
	// CloudKMS is a KMS implementation using Google's Cloud KMS.
	CloudKMS = "cloudkms"
	// AmazonKMS is a KMS implementation using Amazon AWS KMS.
	AmazonKMS = "awskms"
	// PKCS11 is a KMS implementation using the PKCS11 standard.
	PKCS11 = "pkcs11"
)

type Options struct {
	Type            string `json:"type"`
	CredentialsFile string `json:"credentialsFile"`
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
