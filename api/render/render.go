// Package render implements functionality related to response rendering.
package render

import (
	"encoding/json"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/log"
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
