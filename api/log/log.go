// Package log implements API-related logging helpers.
package log

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/logging"
)

// StackTracedError is the set of errors implementing the StackTrace function.
//
// Errors implementing this interface have their stack traces logged when passed
// to the Error function of this package.
type StackTracedError interface {
	error

	StackTrace() errors.StackTrace
}

// AsStackTracedError attempts to return the input error cast to a
// StackTracedError interface.
func AsStackTracedError(err error) (StackTracedError, bool) {
	//nolint:errorlint // ignore type assertion warning. casting to interface is hard.
	if st, ok := err.(StackTracedError); ok {
		return st, ok
	}
	return nil, false
}

// Error adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func Error(rw http.ResponseWriter, err error) {
	rl, ok := rw.(logging.ResponseLogger)
	if !ok {
		return
	}

	rl.WithFields(map[string]interface{}{
		"error": err,
	})

	if os.Getenv("STEPDEBUG") != "1" {
		return
	}

	e, ok := AsStackTracedError(err)
	if !ok {
		//nolint:errorlint // ignore type assertion warning. casting to interface is hard.
		e, ok = errors.Cause(err).(StackTracedError)
	}

	if ok {
		rl.WithFields(map[string]interface{}{
			"stack-trace": fmt.Sprintf("%+v", e.StackTrace()),
		})
	}
}

// EnabledResponse log the response object if it implements the EnableLogger
// interface.
func EnabledResponse(rw http.ResponseWriter, v interface{}) {
	type enableLogger interface {
		ToLog() (interface{}, error)
	}

	if el, ok := v.(enableLogger); ok {
		out, err := el.ToLog()
		if err != nil {
			Error(rw, err)

			return
		}

		if rl, ok := rw.(logging.ResponseLogger); ok {
			rl.WithFields(map[string]interface{}{
				"response": out,
			})
		}
	}
}
