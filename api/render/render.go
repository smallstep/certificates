// Package render implements functionality related to response rendering.
package render

import (
	"bytes"
	"encoding/json"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/errs"
)

// JSON is shorthand for JSONStatus(w, v, http.StatusOK).
func JSON(w http.ResponseWriter, v interface{}) {
	JSONStatus(w, v, http.StatusOK)
}

// JSONStatus marshals v into w. It additionally sets the status code of
// w to the given one.
//
// JSONStatus sets the Content-Type of w to application/json unless one is
// specified.
func JSONStatus(w http.ResponseWriter, v interface{}, status int) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(v); err != nil {
		panic(err)
	}

	setContentTypeUnlessPresent(w, "application/json")
	w.WriteHeader(status)
	_, _ = b.WriteTo(w)

	log.EnabledResponse(w, v)
}

// ProtoJSON is shorthand for ProtoJSONStatus(w, m, http.StatusOK).
func ProtoJSON(w http.ResponseWriter, m proto.Message) {
	ProtoJSONStatus(w, m, http.StatusOK)
}

// ProtoJSONStatus writes the given value into the http.ResponseWriter and the
// given status is written as the status code of the response.
func ProtoJSONStatus(w http.ResponseWriter, m proto.Message, status int) {
	b, err := protojson.Marshal(m)
	if err != nil {
		panic(err)
	}

	setContentTypeUnlessPresent(w, "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func setContentTypeUnlessPresent(w http.ResponseWriter, contentType string) {
	const header = "Content-Type"

	h := w.Header()
	if _, ok := h[header]; !ok {
		h.Set(header, contentType)
	}
}

// Error encodes the JSON representation of err to w.
func Error(w http.ResponseWriter, err error) {
	log.Error(w, err)

	switch k := err.(type) {
	case *acme.Error:
		acme.WriteError(w, k)
		return
	case *admin.Error:
		admin.WriteError(w, k)
		return
	}

	code := http.StatusInternalServerError
	if sc, ok := err.(errs.StatusCoder); ok {
		code = sc.StatusCode()
	} else if sc, ok := errors.Cause(err).(errs.StatusCoder); ok {
		code = sc.StatusCode()
	}

	JSONStatus(w, err, code)
}
