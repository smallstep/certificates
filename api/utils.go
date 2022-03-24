package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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

// JSONNotFound writes a HTTP Not Found response with empty body.
func JSONNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	LogEnabledResponse(w, nil)
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
		LogError(w, err)
		return
	}
	if _, err := w.Write(b); err != nil {
		LogError(w, err)
		return
	}
	//LogEnabledResponse(w, v)
}

// ReadJSON reads JSON from the request body and stores it in the value
// pointed by v.
func ReadJSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return errs.BadRequestErr(err, "error decoding json")
	}
	return nil
}

// ReadProtoJSON reads JSON from the request body and stores it in the value
// pointed by v.
func ReadProtoJSON(r io.Reader, m proto.Message) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errs.BadRequestErr(err, "error reading request body")
	}
	return protojson.Unmarshal(data, m)
}

// ReadProtoJSONWithCheck reads JSON from the request body and stores it in the value
// pointed by v. TODO(hs): move this to and integrate with render package.
func ReadProtoJSONWithCheck(w http.ResponseWriter, r io.Reader, m proto.Message) bool {
	data, err := io.ReadAll(r)
	if err != nil {
		var wrapper = struct {
			Status  int    `json:"code"`
			Message string `json:"message"`
		}{
			Status:  http.StatusBadRequest,
			Message: err.Error(),
		}
		data, err := json.Marshal(wrapper) // TODO(hs): handle err; even though it's very unlikely to fail
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(data)
		return false
	}
	if err := protojson.Unmarshal(data, m); err != nil {
		if errors.Is(err, proto.Error) {
			var wrapper = struct {
				Message string `json:"message"`
			}{
				Message: err.Error(),
			}
			data, err := json.Marshal(wrapper) // TODO(hs): handle err; even though it's very unlikely to fail
			if err != nil {
				panic(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(data)
			return false
		}

		// fallback to the default error writer
		WriteError(w, err)
		return false
	}

	return true
}
