package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// EnableLogger is an interface that enables response logging for an object.
type EnableLogger interface {
	ToLog() (interface{}, error)
}

// LogError adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func LogError(rw http.ResponseWriter, err error) {
	if rl, ok := rw.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"error": err,
		})
	} else {
		log.Println(err)
	}
}

// LogEnabledResponse log the response object if it implements the EnableLogger
// interface.
func LogEnabledResponse(rw http.ResponseWriter, v interface{}) {
	if el, ok := v.(EnableLogger); ok {
		out, err := el.ToLog()
		if err != nil {
			LogError(rw, err)
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
		LogError(w, err)
		return
	}
	LogEnabledResponse(w, v)
}

// ReadJSON reads JSON from the request body and stores it in the value
// pointed by v.
func ReadJSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return errs.Wrap(http.StatusBadRequest, err, "error decoding json")
	}
	return nil
}
