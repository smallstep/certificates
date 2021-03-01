// Error represents an ACME
package acme

import (
	"fmt"

	"github.com/pkg/errors"
)

// ProblemType is the type of the ACME problem.
type ProblemType int

const (
	// The request specified an account that does not exist
	ErrorAccountDoesNotExistType ProblemType = iota
	// The request specified a certificate to be revoked that has already been revoked
	ErrorAlreadyRevokedType
	// The CSR is unacceptable (e.g., due to a short key)
	ErrorBadCSRType
	// The client sent an unacceptable anti-replay nonce
	ErrorBadNonceType
	// The JWS was signed by a public key the server does not support
	ErrorBadPublicKeyType
	// The revocation reason provided is not allowed by the server
	ErrorBadRevocationReasonType
	// The JWS was signed with an algorithm the server does not support
	ErrorBadSignatureAlgorithmType
	// Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate
	ErrorCaaType
	// Specific error conditions are indicated in the “subproblems” array.
	ErrorCompoundType
	// The server could not connect to validation target
	ErrorConnectionType
	// There was a problem with a DNS query during identifier validation
	ErrorDNSType
	// The request must include a value for the “externalAccountBinding” field
	ErrorExternalAccountRequiredType
	// Response received didn’t match the challenge’s requirements
	ErrorIncorrectResponseType
	// A contact URL for an account was invalid
	ErrorInvalidContactType
	// The request message was malformed
	ErrorMalformedType
	// The request attempted to finalize an order that is not ready to be finalized
	ErrorOrderNotReadyType
	// The request exceeds a rate limit
	ErrorRateLimitedType
	// The server will not issue certificates for the identifier
	ErrorRejectedIdentifierType
	// The server experienced an internal error
	ErrorServerInternalType
	// The server received a TLS error during validation
	ErrorTLSType
	// The client lacks sufficient authorization
	ErrorUnauthorizedType
	// A contact URL for an account used an unsupported protocol scheme
	ErrorUnsupportedContactType
	// An identifier is of an unsupported type
	ErrorUnsupportedIdentifierType
	// Visit the “instance” URL and take actions specified there
	ErrorUserActionRequiredType
	// The operation is not implemented
	ErrorNotImplementedType
)

// String returns the string representation of the acme problem type,
// fulfilling the Stringer interface.
func (ap ProblemType) String() string {
	switch ap {
	case ErrorAccountDoesNotExistType:
		return "accountDoesNotExist"
	case ErrorAlreadyRevokedType:
		return "alreadyRevoked"
	case ErrorBadCSRType:
		return "badCSR"
	case ErrorBadNonceType:
		return "badNonce"
	case ErrorBadPublicKeyType:
		return "badPublicKey"
	case ErrorBadRevocationReasonType:
		return "badRevocationReason"
	case ErrorBadSignatureAlgorithmType:
		return "badSignatureAlgorithm"
	case ErrorCaaType:
		return "caa"
	case ErrorCompoundType:
		return "compound"
	case ErrorConnectionType:
		return "connection"
	case ErrorDNSType:
		return "dns"
	case ErrorExternalAccountRequiredType:
		return "externalAccountRequired"
	case ErrorInvalidContactType:
		return "incorrectResponse"
	case ErrorInvalidContactType:
		return "invalidContact"
	case ErrorMalformedType:
		return "malformed"
	case ErrorOrderNotReadyType:
		return "orderNotReady"
	case ErrorRateLimitedType:
		return "rateLimited"
	case ErrorRejectedIdentifierType:
		return "rejectedIdentifier"
	case ErrorServerInternalType:
		return "serverInternal"
	case ErrorTLSType:
		return "tls"
	case ErrorUnauthorizedType:
		return "unauthorized"
	case ErrorUnsupportedContactType:
		return "unsupportedContact"
	case ErrorUnsupportedIdentifierType:
		return "unsupportedIdentifier"
	case ErrorUserActionRequiredType:
		return "userActionRequired"
	case ErrorNotImplementedType:
		return "notImplemented"
	default:
		return fmt.Sprintf("unsupported type ACME error type %v", ap)
	}
}

type errorMetadata struct {
	details string
	status  int
	typ     string
	String  string
}

var (
	officialACMEPrefix          = "urn:ietf:params:acme:error:"
	stepACMEPrefix              = "urn:step:acme:error:"
	errorServerInternalMetadata = errorMetadata{
		ErrorAccountDoesNotExistType: {
			typ:     officialACMEPrefix + ErrorServerInternalType.String(),
			details: "The server experienced an internal error",
			status:  500,
		},
	}
	errorMap = [ProblemType]errorMetadata{
		ErrorAccountDoesNotExistType: {
			typ:     officialACMEPrefix + ErrorAccountDoesNotExistType.String(),
			details: "Account does not exist",
			status:  400,
		},
		ErrorAlreadyRevokedType: {
			typ:     officialACMEPrefix + ErrorAlreadyRevokedType.String(),
			details: "Certificate already Revoked",
			status:  400,
		},
		ErrorBadCSRType: {
			typ:     officialACMEPrefix + ErrorBadCSRType.String(),
			details: "The CSR is unacceptable",
			status:  400,
		},
		ErrorBadNonceType: {
			typ:     officialACMEPrefix + ErrorBadNonceType.String(),
			details: "Unacceptable anti-replay nonce",
			status:  400,
		},
		ErrorBadPublicKeyType: {
			typ:     officialACMEPrefix + ErrorBadPublicKeyType.String(),
			details: "The jws was signed by a public key the server does not support",
			status:  400,
		},
		ErrorBadRevocationReasonType: {
			typ:     officialACMEPrefix + ErrorBadRevocationReasonType.String(),
			details: "The revocation reason provided is not allowed by the server",
			status:  400,
		},
		ErrorBadSignatureAlgorithmType: {
			typ:     officialACMEPrefix + ErrorBadSignatureAlgorithmType.String(),
			details: "The JWS was signed with an algorithm the server does not support",
			status:  400,
		},
		ErrorCaaType: {
			typ:     officialACMEPrefix + ErrorCaaType.String(),
			details: "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate",
			status:  400,
		},
		ErrorCompoundType: {
			typ:     officialACMEPrefix + ErrorCompoundType.String(),
			details: "Specific error conditions are indicated in the “subproblems” array",
			status:  400,
		},
		ErrorConnectionType: {
			typ:     officialACMEPrefix + ErrorConnectionType.String(),
			details: "The server could not connect to validation target",
			status:  400,
		},
		ErrorDNSType: {
			typ:     officialACMEPrefix + ErrorDNSType.String(),
			details: "There was a problem with a DNS query during identifier validation",
			status:  400,
		},
		ErrorExternalAccountRequiredType: {
			typ:     officialACMEPrefix + ErrorExternalAccountRequiredType.String(),
			details: "The request must include a value for the \"externalAccountBinding\" field",
			status:  400,
		},
		ErrorIncorrectResponseType: {
			typ:     officialACMEPrefix + ErrorIncorrectResponseType.String(),
			details: "Response received didn't match the challenge's requirements",
			status:  400,
		},
		ErrorInvalidContactType: {
			typ:     officialACMEPrefix + ErrorInvalidContactType.String(),
			details: "A contact URL for an account was invalid",
			status:  400,
		},
		ErrorMalformedType: {
			typ:     officialACMEPrefix + ErrorMalformedType.String(),
			details: "The request message was malformed",
			status:  400,
		},
		ErrorOrderNotReadyType: {
			typ:     officialACMEPrefix + ErrorOrderNotReadyType.String(),
			details: "The request attempted to finalize an order that is not ready to be finalized",
			status:  400,
		},
		ErrorRateLimitedType: {
			typ:     officialACMEPrefix + ErrorRateLimitedType.String(),
			details: "The request exceeds a rate limit",
			status:  400,
		},
		ErrorRejectedIdentifierType: {
			typ:     officialACMEPrefix + ErrorRejectedIdentifierType.String(),
			details: "The server will not issue certificates for the identifier",
			status:  400,
		},
		ErrorNotImplementedType: {
			typ:     officialACMEPrefix + ErrorRejectedIdentifierType.String(),
			details: "The requested operation is not implemented",
			status:  501,
		},
		ErrorTLSType: {
			typ:     officialACMEPrefix + ErrorTLSType.String(),
			details: "The server received a TLS error during validation",
			status:  400,
		},
		ErrorUnauthorizedType: {
			typ:     officialACMEPrefix + ErrorUnauthorizedType.String(),
			details: "The client lacks sufficient authorization",
			status:  401,
		},
		ErrorUnsupportedContactType: {
			typ:     officialACMEPrefix + ErrorUnsupportedContactType.String(),
			details: "A contact URL for an account used an unsupported protocol scheme",
			status:  400,
		},
		ErrorUnsupportedIdentifierType: {
			typ:     officialACMEPrefix + ErrorUnsupportedIdentifierType.String(),
			details: "An identifier is of an unsupported type",
			status:  400,
		},
		ErrorUserActionRequiredType: {
			typ:     officialACMEPrefix + ErrorUserActionRequiredType.String(),
			details: "Visit the “instance” URL and take actions specified there",
			status:  400,
		},
		ErrorServerInternalType: errorServerInternalMetadata,
	}
)

// Error represents an ACME
type Error struct {
	Type        string        `json:"type"`
	Detail      string        `json:"detail"`
	Subproblems []interface{} `json:"subproblems,omitempty"`
	Identifier  interface{}   `json:"identifier,omitempty"`
	Err         error         `json:"-"`
	Status      int           `json:"-"`
}

func NewError(pt ProblemType, msg string, args ...interface{}) *Error {
	meta, ok := errorMetadata[typ]
	if !ok {
		meta = errorServerInternalMetadata
		return &Error{
			Type:    meta.typ,
			Details: meta.details,
			Status:  meta.Status,
			Err:     errors.Errorf("unrecognized problemType %v", pt),
		}
	}

	return &Error{
		Type:    meta.typ,
		Details: meta.details,
		Status:  meta.status,
		Err:     errors.Errorf(msg, args...),
	}
}

// ErrorWrap attempts to wrap the internal error.
func ErrorWrap(typ ProblemType, err error, msg string, args ...interface{}) *Error {
	switch e := err.(type) {
	case nil:
		return nil
	case *Error:
		if e.Err == nil {
			e.Err = errors.Errorf(msg+"; "+e.Detail, args...)
		} else {
			e.Err = errors.Wrapf(e.Err, msg, args...)
		}
		return e
	default:
		return NewError(ErrorServerInternalType, msg, args...)
	}
}

// StatusCode returns the status code and implements the StatusCoder interface.
func (e *Error) StatusCode() int {
	return e.Status
}

// Error allows AError to implement the error interface.
func (e *Error) Error() string {
	return e.Detail
}

// Cause returns the internal error and implements the Causer interface.
func (e *Error) Cause() error {
	if e.Err == nil {
		return errors.New(e.Detail)
	}
	return e.Err
}
