// Package read implements request object readers.
package read

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/errs"
)

// JSON reads JSON from the request body and stores it in the value
// pointed to by v.
func JSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return errs.BadRequestErr(err, "error decoding json")
	}
	return nil
}

// ProtoJSON reads JSON from the request body and stores it in the value
// pointed to by m.
func ProtoJSON(r io.Reader, m proto.Message) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errs.BadRequestErr(err, "error reading request body")
	}

	switch err := protojson.Unmarshal(data, m); {
	case errors.Is(err, proto.Error):
		return badProtoJSONError(err.Error())
	default:
		return err
	}
}

// badProtoJSONError is an error type that is returned by ProtoJSON
// when a proto message cannot be unmarshaled. Usually this is caused
// by an error in the request body.
type badProtoJSONError string

// Error implements error for badProtoJSONError
func (e badProtoJSONError) Error() string {
	return string(e)
}

// Render implements render.RenderableError for badProtoJSONError
func (e badProtoJSONError) Render(w http.ResponseWriter) {
	v := struct {
		Type    string `json:"type"`
		Detail  string `json:"detail"`
		Message string `json:"message"`
	}{
		Type:   "badRequest",
		Detail: "bad request",
		// trim the proto prefix for the message
		Message: strings.TrimSpace(strings.TrimPrefix(e.Error(), "proto:")),
	}
	render.JSONStatus(w, v, http.StatusBadRequest)
}
