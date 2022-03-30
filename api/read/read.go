// Package read implements request object readers.
package read

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/render"
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
// pointed by v.
func ProtoJSON(r io.Reader, m proto.Message) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errs.BadRequestErr(err, "error reading request body")
	}
	return protojson.Unmarshal(data, m)
}

// ProtoJSONWithCheck reads JSON from the request body and stores it in the value
// pointed to by v. Returns false if an error was written; true if not.
func ProtoJSONWithCheck(w http.ResponseWriter, r io.Reader, m proto.Message) bool {
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
		render.Error(w, err)
		return false
	}

	return true
}
