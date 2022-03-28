// Package log implements API-related logging helpers.
package log

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// Error adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func Error(rw http.ResponseWriter, err error) {
	rl, ok := rw.(logging.ResponseLogger)
	if !ok {
		log.Println(err)

		return
	}

	rl.WithFields(map[string]interface{}{
		"error": err,
	})

	if os.Getenv("STEPDEBUG") != "1" {
		return
	}

	e, ok := err.(errs.StackTracer)
	if !ok {
		e, ok = cause(err).(errs.StackTracer)
	}

	if ok {
		rl.WithFields(map[string]interface{}{
			"stack-trace": fmt.Sprintf("%+v", e),
		})
	}
}

func cause(err error) error {
	type causer interface {
		Cause() error
	}

	for err != nil {
		cause, ok := err.(causer)
		if !ok {
			break
		}
		err = cause.Cause()
	}
	return err
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
		} else {
			log.Println(out)
		}
	}
}
