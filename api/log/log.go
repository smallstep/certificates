// Package log implements API-related logging helpers.
package log

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

// ErrorKey is the logging attribute key for error values.
const ErrorKey = "error"

type loggerKey struct{}

// NewContext creates a new context with the given slog.Logger.
func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// FromContext returns the logger from the given context.
func FromContext(ctx context.Context) (l *slog.Logger, ok bool) {
	l, ok = ctx.Value(loggerKey{}).(*slog.Logger)
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
func Error(rw http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	if logger, ok := FromContext(ctx); ok && err != nil {
		logger.ErrorContext(ctx, "request failed", slog.Any(ErrorKey, err))
	}

	fc, ok := rw.(fieldCarrier)
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
