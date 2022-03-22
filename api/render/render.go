// Package render implements functionality related to response rendering.
package render

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/scep"
)

// JSON writes the passed value into the http.ResponseWriter.
func JSON(w http.ResponseWriter, v interface{}) {
	JSONStatus(w, v, http.StatusOK)
}

// JSONStatus writes the given value into the http.ResponseWriter and the
// given status is written as the status code of the response.
func JSONStatus(w http.ResponseWriter, v interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error(w, err)

		return
	}

	log.EnabledResponse(w, v)
}

// ProtoJSON writes the passed value into the http.ResponseWriter.
func ProtoJSON(w http.ResponseWriter, m proto.Message) {
	ProtoJSONStatus(w, m, http.StatusOK)
}

// ProtoJSONStatus writes the given value into the http.ResponseWriter and the
// given status is written as the status code of the response.
func ProtoJSONStatus(w http.ResponseWriter, m proto.Message, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	b, err := protojson.Marshal(m)
	if err != nil {
		log.Error(w, err)

		return
	}

	if _, err := w.Write(b); err != nil {
		log.Error(w, err)

		return
	}

	// log.EnabledResponse(w, v)
}

// Error encodes the JSON representation of err to w.
func Error(w http.ResponseWriter, err error) {
	switch k := err.(type) {
	case *acme.Error:
		acme.WriteError(w, k)
		return
	case *admin.Error:
		admin.WriteError(w, k)
		return
	case *scep.Error:
		w.Header().Set("Content-Type", "text/plain")
	default:
		w.Header().Set("Content-Type", "application/json")
	}

	cause := errors.Cause(err)
	if sc, ok := err.(errs.StatusCoder); ok {
		w.WriteHeader(sc.StatusCode())
	} else {
		if sc, ok := cause.(errs.StatusCoder); ok {
			w.WriteHeader(sc.StatusCode())
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

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

	if err := json.NewEncoder(w).Encode(err); err != nil {
		log.Error(w, err)
	}
}

// BadRequest renders the JSON representation of err into w and sets its
// status code to http.StatusBadRequest.
//
// In case err is nil, a default error message will be used in its place.
func BadRequest(w http.ResponseWriter, err error) {
	codedError(w, http.StatusBadRequest, err)
}

func codedError(w http.ResponseWriter, code int, err error) {
	if err == nil {
		err = errors.New(http.StatusText(code))
	}

	var wrapper = struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}{
		Status:  code,
		Message: err.Error(),
	}

	data, err := json.Marshal(wrapper)
	if err != nil {
		log.Error(w, err)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}
