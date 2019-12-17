package errs

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// StatusCoder interface is used by errors that returns the HTTP response code.
type StatusCoder interface {
	StatusCode() int
}

// StackTracer must be by those errors that return an stack trace.
type StackTracer interface {
	StackTrace() errors.StackTrace
}

// Option modifies the Error type.
type Option func(e *Error) error

// WithMessage returns an Option that modifies the error by overwriting the
// message only if it is empty.
func WithMessage(format string, args ...interface{}) Option {
	return func(e *Error) error {
		if len(e.Msg) > 0 {
			return e
		}
		e.Msg = fmt.Sprintf(format, args...)
		return e
	}
}

// Error represents the CA API errors.
type Error struct {
	Status int
	Err    error
	Msg    string
}

// New returns a new Error. If the given error implements the StatusCoder
// interface we will ignore the given status.
func New(status int, err error, opts ...Option) error {
	var e *Error
	if sc, ok := err.(StatusCoder); ok {
		e = &Error{Status: sc.StatusCode(), Err: err}
	} else {
		cause := errors.Cause(err)
		if sc, ok := cause.(StatusCoder); ok {
			e = &Error{Status: sc.StatusCode(), Err: err}
		} else {
			e = &Error{Status: status, Err: err}
		}
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// ErrorResponse represents an error in JSON format.
type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// Cause implements the errors.Causer interface and returns the original error.
func (e *Error) Cause() error {
	return e.Err
}

// Error implements the error interface and returns the error string.
func (e *Error) Error() string {
	return e.Err.Error()
}

// StatusCode implements the StatusCoder interface and returns the HTTP response
// code.
func (e *Error) StatusCode() int {
	return e.Status
}

// Message returns a user friendly error, if one is set.
func (e *Error) Message() string {
	if len(e.Msg) > 0 {
		return e.Msg
	}
	return e.Err.Error()
}

// Wrap returns an error annotating err with a stack trace at the point Wrap is
// called, and the supplied message. If err is nil, Wrap returns nil.
func Wrap(status int, e error, m string, opts ...Option) error {
	if e == nil {
		return nil
	}
	if err, ok := e.(*Error); ok {
		err.Err = errors.Wrap(err.Err, m)
		e = err
	} else {
		e = errors.Wrap(e, m)
	}
	return StatusCodeError(status, e, opts...)
}

// Wrapf returns an error annotating err with a stack trace at the point Wrap is
// called, and the supplied message. If err is nil, Wrap returns nil.
func Wrapf(status int, e error, format string, args ...interface{}) error {
	if e == nil {
		return nil
	}
	var opts []Option
	for i, arg := range args {
		// Once we find the first Option, assume that all further arguments are Options.
		if _, ok := arg.(Option); ok {
			for _, a := range args[i:] {
				// Ignore any arguments after the first Option that are not Options.
				if opt, ok := a.(Option); ok {
					opts = append(opts, opt)
				}
			}
			args = args[:i]
			break
		}
	}
	if err, ok := e.(*Error); ok {
		err.Err = errors.Wrapf(err.Err, format, args...)
		e = err
	} else {
		e = errors.Wrapf(e, format, args...)
	}
	return StatusCodeError(status, e, opts...)
}

// MarshalJSON implements json.Marshaller interface for the Error struct.
func (e *Error) MarshalJSON() ([]byte, error) {
	var msg string
	if len(e.Msg) > 0 {
		msg = e.Msg
	} else {
		msg = http.StatusText(e.Status)
	}
	return json.Marshal(&ErrorResponse{Status: e.Status, Message: msg})
}

// UnmarshalJSON implements json.Unmarshaler interface for the Error struct.
func (e *Error) UnmarshalJSON(data []byte) error {
	var er ErrorResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return err
	}
	e.Status = er.Status
	e.Err = fmt.Errorf(er.Message)
	return nil
}

// Format implements the fmt.Formatter interface.
func (e *Error) Format(f fmt.State, c rune) {
	if err, ok := e.Err.(fmt.Formatter); ok {
		err.Format(f, c)
		return
	}
	fmt.Fprint(f, e.Err.Error())
}

// Messenger is a friendly message interface that errors can implement.
type Messenger interface {
	Message() string
}

// StatusCodeError selects the proper error based on the status code.
func StatusCodeError(code int, e error, opts ...Option) error {
	switch code {
	case http.StatusBadRequest:
		return BadRequest(e, opts...)
	case http.StatusUnauthorized:
		return Unauthorized(e, opts...)
	case http.StatusForbidden:
		return Forbidden(e, opts...)
	case http.StatusInternalServerError:
		return InternalServerError(e, opts...)
	case http.StatusNotImplemented:
		return NotImplemented(e, opts...)
	default:
		return UnexpectedError(code, e, opts...)
	}
}

var seeLogs = "Please see the certificate authority logs for more info."

// InternalServerError returns a 500 error with the given error.
func InternalServerError(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The certificate authority encountered an Internal Server Error. "+seeLogs))
	}
	return New(http.StatusInternalServerError, err, opts...)
}

// NotImplemented returns a 501 error with the given error.
func NotImplemented(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The requested method is not implemented by the certificate authority. "+seeLogs))
	}
	return New(http.StatusNotImplemented, err, opts...)
}

// BadRequest returns an 400 error with the given error.
func BadRequest(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The request could not be completed due to being poorly formatted or "+
			"missing critical data. "+seeLogs))
	}
	return New(http.StatusBadRequest, err, opts...)
}

// Unauthorized returns an 401 error with the given error.
func Unauthorized(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The request lacked necessary authorization to be completed. "+seeLogs))
	}
	return New(http.StatusUnauthorized, err, opts...)
}

// Forbidden returns an 403 error with the given error.
func Forbidden(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The request was Forbidden by the certificate authority. "+seeLogs))
	}
	return New(http.StatusForbidden, err, opts...)
}

// NotFound returns an 404 error with the given error.
func NotFound(err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The requested resource could not be found. "+seeLogs))
	}
	return New(http.StatusNotFound, err, opts...)
}

// UnexpectedError will be used when the certificate authority makes an outgoing
// request and receives an unhandled status code.
func UnexpectedError(code int, err error, opts ...Option) error {
	if len(opts) == 0 {
		opts = append(opts, WithMessage("The certificate authority received an "+
			"unexpected HTTP status code - '%d'. "+seeLogs, code))
	}
	return New(code, err, opts...)
}
