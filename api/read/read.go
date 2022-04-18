// Package read implements request object readers.
package read

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/errs"
)

// JSON reads JSON from the request body and stores it in the value
// pointed by v.
func JSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return errs.BadRequestErr(err, "error decoding json")
	}
	return nil
}

// ProtoJSON reads JSON from the request body and stores it in the value
// pointed to by v.
func ProtoJSON(r io.Reader, m proto.Message) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errs.BadRequestErr(err, "error reading request body")
	}
	if err := protojson.Unmarshal(data, m); err != nil {
		if errors.Is(err, proto.Error) {
			return newBadProtoJSONError(err)
		}
	}
	return err
}

// BadProtoJSONError is an error type that is used when a proto
// message cannot be unmarshaled. Usually this is caused by an error
// in the request body.
type BadProtoJSONError struct {
	err     error
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Message string `json:"message"`
}

// newBadProtoJSONError returns a new instance of BadProtoJSONError
// This error type is always caused by an error in the request body.
func newBadProtoJSONError(err error) *BadProtoJSONError {
	return &BadProtoJSONError{
		err:     err,
		Type:    "badRequest",
		Detail:  "bad request",
		Message: err.Error(),
	}
}

// Error implements the error interface
func (e *BadProtoJSONError) Error() string {
	return e.err.Error()
}

// Render implements render.RenderableError for BadProtoError
func (e *BadProtoJSONError) Render(w http.ResponseWriter) {

	errData, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(errData)
}
