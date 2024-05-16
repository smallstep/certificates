// Package log implements API-related logging helpers.
package log

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

type errorLoggerKey struct{}

// ErrorLogger is the function type used to log errors.
type ErrorLogger func(http.ResponseWriter, *http.Request, error)

func (fn ErrorLogger) call(w http.ResponseWriter, r *http.Request, err error) {
	if fn == nil {
		return
	}
	fn(w, r, err)
}

// WithErrorLogger returns a new context with the given error logger.
func WithErrorLogger(ctx context.Context, fn ErrorLogger) context.Context {
	return context.WithValue(ctx, errorLoggerKey{}, fn)
}

// ErrorLoggerFromContext returns an error logger from the context.
func ErrorLoggerFromContext(ctx context.Context) (fn ErrorLogger) {
	fn, _ = ctx.Value(errorLoggerKey{}).(ErrorLogger)
	return
}

// StackTracedError is the set of errors implementing the StackTrace function.
//
// Errors implementing this interface have their stack traces logged when passed
// to the Error function of this package.
type StackTracedError interface {
	error

	StackTrace() errors.StackTrace
}

type fieldCarrier interface {
	WithFields(map[string]any)
	Fields() map[string]any
}

// Error adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	ErrorLoggerFromContext(r.Context()).call(w, r, err)

	fc, ok := w.(fieldCarrier)
	if !ok {
		return
	}

	fc.WithFields(map[string]any{
		"error": err,
	})

	if os.Getenv("STEPDEBUG") != "1" {
		return
	}

	var st StackTracedError
	if errors.As(err, &st) {
		fc.WithFields(map[string]any{
			"stack-trace": fmt.Sprintf("%+v", st.StackTrace()),
		})
	}
}

// EnabledResponse log the response object if it implements the EnableLogger
// interface.
func EnabledResponse(rw http.ResponseWriter, r *http.Request, v any) {
	type enableLogger interface {
		ToLog() (any, error)
	}

	if el, ok := v.(enableLogger); ok {
		out, err := el.ToLog()
		if err != nil {
			Error(rw, r, err)

			return
		}

		if rl, ok := rw.(fieldCarrier); ok {
			rl.WithFields(map[string]any{
				"response": out,
			})
		}
	}
}
