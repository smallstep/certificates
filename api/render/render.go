// Package render implements functionality related to response rendering.
package render

import (
	"encoding/json"
	"errors"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/log"
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
	setContentTypeUnlessPresent(w, "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		var errUnsupportedType *json.UnsupportedTypeError
		if errors.As(err, &errUnsupportedType) {
			panic(err)
		}

		var errUnsupportedValue *json.UnsupportedValueError
		if errors.As(err, &errUnsupportedValue) {
			panic(err)
		}

		var errMarshalError *json.MarshalerError
		if errors.As(err, &errMarshalError) {
			panic(err)
		}
	}

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

// RenderableError is the set of errors that implement the basic Render method.
//
// Errors that implement this interface will use their own Render method when
// being rendered into responses.
type RenderableError interface {
	error

	Render(http.ResponseWriter)
}

// Error marshals the JSON representation of err to w. In case err implements
// RenderableError its own Render method will be called instead.
func Error(w http.ResponseWriter, err error) {
	log.Error(w, err)

	var r RenderableError
	if errors.As(err, &r) {
		r.Render(w)

		return
	}

	JSONStatus(w, err, statusCodeFromError(err))
}

// StatusCodedError is the set of errors that implement the basic StatusCode
// function.
//
// Errors that implement this interface will use the code reported by StatusCode
// as the HTTP response code when being rendered by this package.
type StatusCodedError interface {
	error

	StatusCode() int
}

func statusCodeFromError(err error) (code int) {
	code = http.StatusInternalServerError

	type causer interface {
		Cause() error
	}

	for err != nil {
		var sc StatusCodedError
		if errors.As(err, &sc) {
			code = sc.StatusCode()

			break
		}

		var c causer
		if !errors.As(err, &c) {
			break
		}
		err = c.Cause()
	}

	return
}
