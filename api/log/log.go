// Package log implements API-related logging helpers.
package log

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

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
func Error(rw http.ResponseWriter, err error) {
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
func EnabledResponse(rw http.ResponseWriter, v any) {
	type enableLogger interface {
		ToLog() (any, error)
	}

	if el, ok := v.(enableLogger); ok {
		out, err := el.ToLog()
		if err != nil {
			Error(rw, err)

			return
		}

		if rl, ok := rw.(fieldCarrier); ok {
			rl.WithFields(map[string]any{
				"response": out,
			})
		}
	}
}
