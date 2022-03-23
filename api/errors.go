package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// WriteError writes to w a JSON representation of the given error.
func WriteError(w http.ResponseWriter, err error) {
	switch k := err.(type) {
	case *acme.Error:
		acme.WriteError(w, k)
		return
	case *admin.Error:
		admin.WriteError(w, k)
		return
	}

	cause := errors.Cause(err)

	// Write errors in the response writer
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"error": err,
		})
		if os.Getenv("STEPDEBUG") == "1" {
			if e, ok := err.(errs.StackTracer); ok {
				rl.WithFields(map[string]interface{}{
					"stack-trace": fmt.Sprintf("%+v", e),
				})
			} else if e, ok := cause.(errs.StackTracer); ok {
				rl.WithFields(map[string]interface{}{
					"stack-trace": fmt.Sprintf("%+v", e),
				})
			}
		}
	}

	code := http.StatusInternalServerError
	if sc, ok := err.(errs.StatusCoder); ok {
		code = sc.StatusCode()
	} else if sc, ok := cause.(errs.StatusCoder); ok {
		code = sc.StatusCode()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(err); err != nil {
		log.Error(w, err)
	}
}
