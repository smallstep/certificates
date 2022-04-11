// Package read implements request object readers.
package read

import (
	"encoding/json"
	"io"

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
// pointed by v.
func ProtoJSON(r io.Reader, m proto.Message) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errs.BadRequestErr(err, "error reading request body")
	}
	return protojson.Unmarshal(data, m)
}
