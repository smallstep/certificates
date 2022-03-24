package api

import (
	"encoding/json"
	"errors"
	"io"

	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/log"
)

// EnableLogger is an interface that enables response logging for an object.
type EnableLogger interface {
	ToLog() (interface{}, error)
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
		log.Error(w, err)

		return
	}

	log.EnabledResponse(w, v)
}

// JSONNotFound writes a HTTP Not Found response with empty body.
func JSONNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	log.EnabledResponse(w, nil)
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
		errData, err := json.Marshal(wrapper)
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errData)
		return false
	}
	if err := protojson.Unmarshal(data, m); err != nil {
		if errors.Is(err, proto.Error) {
			var wrapper = struct {
				Message string `json:"message"`
			}{
				Message: err.Error(),
			}
			errData, err := json.Marshal(wrapper)
			if err != nil {
				panic(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(errData)
			return false
		}

		// fallback to the default error writer
		WriteError(w, err)
		return false
	}

	return true
}
