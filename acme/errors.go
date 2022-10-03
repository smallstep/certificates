package acme

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api/render"
)

// ProblemType is the type of the ACME problem.
type ProblemType int

const (
	// ErrorAccountDoesNotExistType request specified an account that does not exist
	ErrorAccountDoesNotExistType ProblemType = iota
	// ErrorAlreadyRevokedType request specified a certificate to be revoked that has already been revoked
	ErrorAlreadyRevokedType
	// ErrorBadAttestationStatementType WebAuthn attestation statement could not be verified
	ErrorBadAttestationStatementType
	// ErrorBadCSRType CSR is unacceptable (e.g., due to a short key)
	ErrorBadCSRType
	// ErrorBadNonceType client sent an unacceptable anti-replay nonce
	ErrorBadNonceType
	// ErrorBadPublicKeyType JWS was signed by a public key the server does not support
	ErrorBadPublicKeyType
	// ErrorBadRevocationReasonType revocation reason provided is not allowed by the server
	ErrorBadRevocationReasonType
	// ErrorBadSignatureAlgorithmType JWS was signed with an algorithm the server does not support
	ErrorBadSignatureAlgorithmType
	// ErrorCaaType Authority Authorization (CAA) records forbid the CA from issuing a certificate
	ErrorCaaType
	// ErrorCompoundType error conditions are indicated in the “subproblems” array.
	ErrorCompoundType
	// ErrorConnectionType server could not connect to validation target
	ErrorConnectionType
	// ErrorDNSType was a problem with a DNS query during identifier validation
	ErrorDNSType
	// ErrorExternalAccountRequiredType request must include a value for the “externalAccountBinding” field
	ErrorExternalAccountRequiredType
	// ErrorIncorrectResponseType received didn’t match the challenge’s requirements
	ErrorIncorrectResponseType
	// ErrorInvalidContactType URL for an account was invalid
	ErrorInvalidContactType
	// ErrorMalformedType request message was malformed
	ErrorMalformedType
	// ErrorOrderNotReadyType request attempted to finalize an order that is not ready to be finalized
	ErrorOrderNotReadyType
	// ErrorRateLimitedType request exceeds a rate limit
	ErrorRateLimitedType
	// ErrorRejectedIdentifierType server will not issue certificates for the identifier
	ErrorRejectedIdentifierType
	// ErrorServerInternalType server experienced an internal error
	ErrorServerInternalType
	// ErrorTLSType server received a TLS error during validation
	ErrorTLSType
	// ErrorUnauthorizedType client lacks sufficient authorization
	ErrorUnauthorizedType
	// ErrorUnsupportedContactType URL for an account used an unsupported protocol scheme
	ErrorUnsupportedContactType
	// ErrorUnsupportedIdentifierType identifier is of an unsupported type
	ErrorUnsupportedIdentifierType
	// ErrorUserActionRequiredType the “instance” URL and take actions specified there
	ErrorUserActionRequiredType
	// ErrorNotImplementedType operation is not implemented
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
	case ErrorBadAttestationStatementType:
		return "badAttestationStatement"
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
		return fmt.Sprintf("unsupported type ACME error type '%d'", int(ap))
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
	errorServerInternalMetadata = errorMetadata{
		typ:     officialACMEPrefix + ErrorServerInternalType.String(),
		details: "The server experienced an internal error",
		status:  500,
	}
	errorMap = map[ProblemType]errorMetadata{
		ErrorAccountDoesNotExistType: {
			typ:     officialACMEPrefix + ErrorAccountDoesNotExistType.String(),
			details: "Account does not exist",
			status:  400,
		},
		ErrorAlreadyRevokedType: {
			typ:     officialACMEPrefix + ErrorAlreadyRevokedType.String(),
			details: "Certificate already revoked",
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
		ErrorBadAttestationStatementType: {
			typ:     officialACMEPrefix + ErrorBadAttestationStatementType.String(),
			details: "Attestation statement cannot be verified",
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

// NewError creates a new Error type.
func NewError(pt ProblemType, msg string, args ...interface{}) *Error {
	return newError(pt, errors.Errorf(msg, args...))
}

func newError(pt ProblemType, err error) *Error {
	meta, ok := errorMap[pt]
	if !ok {
		meta = errorServerInternalMetadata
		return &Error{
			Type:   meta.typ,
			Detail: meta.details,
			Status: meta.status,
			Err:    err,
		}
	}

	return &Error{
		Type:   meta.typ,
		Detail: meta.details,
		Status: meta.status,
		Err:    err,
	}
}

// NewErrorISE creates a new ErrorServerInternalType Error.
func NewErrorISE(msg string, args ...interface{}) *Error {
	return NewError(ErrorServerInternalType, msg, args...)
}

// WrapError attempts to wrap the internal error.
func WrapError(typ ProblemType, err error, msg string, args ...interface{}) *Error {
	var e *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &e):
		if e.Err == nil {
			e.Err = errors.Errorf(msg+"; "+e.Detail, args...)
		} else {
			e.Err = errors.Wrapf(e.Err, msg, args...)
		}
		return e
	default:
		return newError(typ, errors.Wrapf(err, msg, args...))
	}
}

// WrapErrorISE shortcut to wrap an internal server error type.
func WrapErrorISE(err error, msg string, args ...interface{}) *Error {
	return WrapError(ErrorServerInternalType, err, msg, args...)
}

// StatusCode returns the status code and implements the StatusCoder interface.
func (e *Error) StatusCode() int {
	return e.Status
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err == nil {
		return e.Detail
	}
	return e.Err.Error()
}

// Cause returns the internal error and implements the Causer interface.
func (e *Error) Cause() error {
	if e.Err == nil {
		return errors.New(e.Detail)
	}
	return e.Err
}

// ToLog implements the EnableLogger interface.
func (e *Error) ToLog() (interface{}, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling acme.Error for logging")
	}
	return string(b), nil
}

// Render implements render.RenderableError for Error.
func (e *Error) Render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	render.JSONStatus(w, e, e.StatusCode())
}
