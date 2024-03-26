package errs

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/api/render"
)

// Option modifies the Error type.
type Option func(e *Error) error

// withDefaultMessage returns an Option that modifies the error by overwriting the
// message only if it is empty.
func withDefaultMessage(format string, args ...interface{}) Option {
	return func(e *Error) error {
		if e.Msg != "" {
			return e
		}
		e.Msg = fmt.Sprintf(format, args...)
		return e
	}
}

// WithMessage returns an Option that modifies the error by overwriting the
// message only if it is empty.
func WithMessage(format string, args ...interface{}) Option {
	return func(e *Error) error {
		e.Msg = fmt.Sprintf(format, args...)
		return e
	}
}

// WithKeyVal returns an Option that adds the given key-value pair to the
// Error details. This is helpful for debugging errors.
func WithKeyVal(key string, val interface{}) Option {
	return func(e *Error) error {
		if e.Details == nil {
			e.Details = make(map[string]interface{})
		}
		e.Details[key] = val
		return e
	}
}

// Error represents the CA API errors.
type Error struct {
	Status    int
	Err       error
	Msg       string
	Details   map[string]interface{}
	RequestID string `json:"-"`
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
	if e.Msg != "" {
		return e.Msg
	}
	return e.Err.Error()
}

// Wrap returns an error annotating err with a stack trace at the point Wrap is
// called, and the supplied message. If err is nil, Wrap returns nil.
func Wrap(status int, e error, m string, args ...interface{}) error {
	if e == nil {
		return nil
	}
	_, opts := splitOptionArgs(args)
	var err *Error
	if errors.As(e, &err) {
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
	as, opts := splitOptionArgs(args)
	var err *Error
	if errors.As(e, &err) {
		err.Err = errors.Wrapf(err.Err, format, args...)
		e = err
	} else {
		e = errors.Wrapf(e, format, as...)
	}
	return StatusCodeError(status, e, opts...)
}

// MarshalJSON implements json.Marshaller interface for the Error struct.
func (e *Error) MarshalJSON() ([]byte, error) {
	var msg string
	if e.Msg != "" {
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
	e.Err = fmt.Errorf("%s", er.Message)
	return nil
}

// Format implements the fmt.Formatter interface.
func (e *Error) Format(f fmt.State, c rune) {
	var fe fmt.Formatter
	if errors.As(e.Err, &fe) {
		fe.Format(f, c)
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
		opts = append(opts, withDefaultMessage(BadRequestDefaultMsg))
		return NewErr(http.StatusBadRequest, e, opts...)
	case http.StatusUnauthorized:
		return UnauthorizedErr(e, opts...)
	case http.StatusForbidden:
		opts = append(opts, withDefaultMessage(ForbiddenDefaultMsg))
		return NewErr(http.StatusForbidden, e, opts...)
	case http.StatusInternalServerError:
		return InternalServerErr(e, opts...)
	case http.StatusNotImplemented:
		return NotImplementedErr(e, opts...)
	default:
		return UnexpectedErr(code, e, opts...)
	}
}

var (
	seeLogs = "Please see the certificate authority logs for more info."
	// BadRequestDefaultMsg 400 default msg
	BadRequestDefaultMsg = "The request could not be completed; malformed or missing data. " + seeLogs
	// UnauthorizedDefaultMsg 401 default msg
	UnauthorizedDefaultMsg = "The request lacked necessary authorization to be completed. " + seeLogs
	// ForbiddenDefaultMsg 403 default msg
	ForbiddenDefaultMsg = "The request was forbidden by the certificate authority. " + seeLogs
	// NotFoundDefaultMsg 404 default msg
	NotFoundDefaultMsg = "The requested resource could not be found. " + seeLogs
	// InternalServerErrorDefaultMsg 500 default msg
	InternalServerErrorDefaultMsg = "The certificate authority encountered an Internal Server Error. " + seeLogs
	// NotImplementedDefaultMsg 501 default msg
	NotImplementedDefaultMsg = "The requested method is not implemented by the certificate authority. " + seeLogs
)

var (
	// BadRequestPrefix is the prefix added to the bad request messages that are
	// directly sent to the cli.
	BadRequestPrefix = "The request could not be completed: "

	// ForbiddenPrefix is the prefix added to the forbidden messates that are
	// sent to the cli.
	ForbiddenPrefix = "The request was forbidden by the certificate authority: "
)

func formatMessage(status int, msg string) string {
	switch status {
	case http.StatusBadRequest:
		return BadRequestPrefix + msg + "."
	case http.StatusForbidden:
		return ForbiddenPrefix + msg + "."
	default:
		return msg
	}
}

// splitOptionArgs splits the variadic length args into string formatting args
// and Option(s) to apply to an Error.
func splitOptionArgs(args []interface{}) ([]interface{}, []Option) {
	indexOptionStart := -1
	for i, a := range args {
		if _, ok := a.(Option); ok {
			indexOptionStart = i
			break
		}
	}

	if indexOptionStart < 0 {
		return args, []Option{}
	}
	opts := []Option{}
	// Ignore any non-Option args that come after the first Option.
	for _, o := range args[indexOptionStart:] {
		if opt, ok := o.(Option); ok {
			opts = append(opts, opt)
		}
	}
	return args[:indexOptionStart], opts
}

// New creates a new http error with the given status and message.
func New(status int, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	return &Error{
		Status: status,
		Msg:    formatMessage(status, msg),
		Err:    errors.New(msg),
	}
}

// NewError creates a new http error with the given error and message.
func NewError(status int, err error, format string, args ...interface{}) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	msg := fmt.Sprintf(format, args...)
	var ste log.StackTracedError
	if !errors.As(err, &ste) {
		err = errors.Wrap(err, msg)
	}
	return &Error{
		Status: status,
		Msg:    formatMessage(status, msg),
		Err:    err,
	}
}

// NewErr returns a new Error. If the given error implements the StatusCoder
// interface we will ignore the given status.
func NewErr(status int, err error, opts ...Option) error {
	var e *Error
	if !errors.As(err, &e) {
		var ste render.StatusCodedError
		if errors.As(err, &ste) {
			e = &Error{Status: ste.StatusCode(), Err: err}
		} else {
			e = &Error{Status: status, Err: err}
		}
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Errorf creates a new error using the given format and status code.
func Errorf(code int, format string, args ...interface{}) error {
	as, opts := splitOptionArgs(args)
	opts = append(opts, withDefaultMessage(NotImplementedDefaultMsg))
	e := &Error{Status: code, Err: fmt.Errorf(format, as...)}
	for _, o := range opts {
		o(e)
	}
	return e
}

// ApplyOptions applies the given options to the error if is the type *Error.
// TODO(mariano): try to get rid of this.
func ApplyOptions(err error, opts ...interface{}) error {
	var e *Error
	if errors.As(err, &e) {
		_, o := splitOptionArgs(opts)
		for _, fn := range o {
			fn(e)
		}
	}
	return err
}

// InternalServer creates a 500 error with the given format and arguments.
func InternalServer(format string, args ...interface{}) error {
	args = append(args, withDefaultMessage(InternalServerErrorDefaultMsg))
	return Errorf(http.StatusInternalServerError, format, args...)
}

// InternalServerErr returns a 500 error with the given error.
func InternalServerErr(err error, opts ...Option) error {
	opts = append(opts, withDefaultMessage(InternalServerErrorDefaultMsg))
	return NewErr(http.StatusInternalServerError, err, opts...)
}

// NotImplemented creates a 501 error with the given format and arguments.
func NotImplemented(format string, args ...interface{}) error {
	args = append(args, withDefaultMessage(NotImplementedDefaultMsg))
	return Errorf(http.StatusNotImplemented, format, args...)
}

// NotImplementedErr returns a 501 error with the given error.
func NotImplementedErr(err error, opts ...Option) error {
	opts = append(opts, withDefaultMessage(NotImplementedDefaultMsg))
	return NewErr(http.StatusNotImplemented, err, opts...)
}

// BadRequest creates a 400 error with the given format and arguments.
func BadRequest(format string, args ...interface{}) error {
	return New(http.StatusBadRequest, format, args...)
}

// BadRequestErr returns an 400 error with the given error.
func BadRequestErr(err error, format string, args ...interface{}) error {
	return NewError(http.StatusBadRequest, err, format, args...)
}

// Unauthorized creates a 401 error with the given format and arguments.
func Unauthorized(format string, args ...interface{}) error {
	args = append(args, withDefaultMessage(UnauthorizedDefaultMsg))
	return Errorf(http.StatusUnauthorized, format, args...)
}

// UnauthorizedErr returns an 401 error with the given error.
func UnauthorizedErr(err error, opts ...Option) error {
	opts = append(opts, withDefaultMessage(UnauthorizedDefaultMsg))
	return NewErr(http.StatusUnauthorized, err, opts...)
}

// Forbidden creates a 403 error with the given format and arguments.
func Forbidden(format string, args ...interface{}) error {
	return New(http.StatusForbidden, format, args...)
}

// ForbiddenErr returns an 403 error with the given error.
func ForbiddenErr(err error, format string, args ...interface{}) error {
	return NewError(http.StatusForbidden, err, format, args...)
}

// NotFound creates a 404 error with the given format and arguments.
func NotFound(format string, args ...interface{}) error {
	args = append(args, withDefaultMessage(NotFoundDefaultMsg))
	return Errorf(http.StatusNotFound, format, args...)
}

// NotFoundErr returns an 404 error with the given error.
func NotFoundErr(err error, opts ...Option) error {
	opts = append(opts, withDefaultMessage(NotFoundDefaultMsg))
	return NewErr(http.StatusNotFound, err, opts...)
}

// UnexpectedErr will be used when the certificate authority makes an outgoing
// request and receives an unhandled status code.
func UnexpectedErr(code int, err error, opts ...Option) error {
	opts = append(opts, withDefaultMessage("The certificate authority received an "+
		"unexpected HTTP status code - '%d'. "+seeLogs, code))
	return NewErr(code, err, opts...)
}
