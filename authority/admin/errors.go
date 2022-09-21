package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api/render"
)

// ProblemType is the type of the Admin problem.
type ProblemType int

const (
	// ErrorNotFoundType resource not found.
	ErrorNotFoundType ProblemType = iota
	// ErrorAuthorityMismatchType resource Authority ID does not match the
	// context Authority ID.
	ErrorAuthorityMismatchType
	// ErrorDeletedType resource has been deleted.
	ErrorDeletedType
	// ErrorBadRequestType bad request.
	ErrorBadRequestType
	// ErrorNotImplementedType not implemented.
	ErrorNotImplementedType
	// ErrorUnauthorizedType unauthorized.
	ErrorUnauthorizedType
	// ErrorServerInternalType internal server error.
	ErrorServerInternalType
	// ErrorConflictType conflict.
	ErrorConflictType
)

// String returns the string representation of the admin problem type,
// fulfilling the Stringer interface.
func (ap ProblemType) String() string {
	switch ap {
	case ErrorNotFoundType:
		return "notFound"
	case ErrorAuthorityMismatchType:
		return "authorityMismatch"
	case ErrorDeletedType:
		return "deleted"
	case ErrorBadRequestType:
		return "badRequest"
	case ErrorNotImplementedType:
		return "notImplemented"
	case ErrorUnauthorizedType:
		return "unauthorized"
	case ErrorServerInternalType:
		return "internalServerError"
	case ErrorConflictType:
		return "conflict"
	default:
		return fmt.Sprintf("unsupported error type '%d'", int(ap))
	}
}

type errorMetadata struct {
	details string
	status  int
	typ     string
	String  string
}

var (
	errorServerInternalMetadata = errorMetadata{
		typ:     ErrorServerInternalType.String(),
		details: "the server experienced an internal error",
		status:  http.StatusInternalServerError,
	}
	errorMap = map[ProblemType]errorMetadata{
		ErrorNotFoundType: {
			typ:     ErrorNotFoundType.String(),
			details: "resource not found",
			status:  http.StatusNotFound,
		},
		ErrorAuthorityMismatchType: {
			typ:     ErrorAuthorityMismatchType.String(),
			details: "resource not owned by authority",
			status:  http.StatusUnauthorized,
		},
		ErrorDeletedType: {
			typ:     ErrorDeletedType.String(),
			details: "resource is deleted",
			status:  http.StatusNotFound,
		},
		ErrorNotImplementedType: {
			typ:     ErrorNotImplementedType.String(),
			details: "not implemented",
			status:  http.StatusNotImplemented,
		},
		ErrorBadRequestType: {
			typ:     ErrorBadRequestType.String(),
			details: "bad request",
			status:  http.StatusBadRequest,
		},
		ErrorUnauthorizedType: {
			typ:     ErrorUnauthorizedType.String(),
			details: "unauthorized",
			status:  http.StatusUnauthorized,
		},
		ErrorServerInternalType: errorServerInternalMetadata,
		ErrorConflictType: {
			typ:     ErrorConflictType.String(),
			details: "conflict",
			status:  http.StatusConflict,
		},
	}
)

// Error represents an Admin error
type Error struct {
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Message string `json:"message"`
	Err     error  `json:"-"`
	Status  int    `json:"-"`
}

// IsType returns true if the error type matches the input type.
func (e *Error) IsType(pt ProblemType) bool {
	return pt.String() == e.Type
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
	var ee *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ee):
		if ee.Err == nil {
			ee.Err = errors.Errorf(msg+"; "+ee.Detail, args...)
		} else {
			ee.Err = errors.Wrapf(ee.Err, msg, args...)
		}
		return ee
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

// Error allows AError to implement the error interface.
func (e *Error) Error() string {
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
		return nil, WrapErrorISE(err, "error marshaling authority.Error for logging")
	}
	return string(b), nil
}

// Render implements render.RenderableError for Error.
func (e *Error) Render(w http.ResponseWriter) {
	e.Message = e.Err.Error()

	render.JSONStatus(w, e, e.StatusCode())
}
