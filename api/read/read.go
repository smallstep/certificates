// Package read implements request object readers.
package read

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"

	"github.com/smallstep/certificates/internal/buffer"
)

// JSON unmarshals from the given request's JSON body into v. In case of an
// error a HTTP Bad Request error will be written to w.
func JSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	b := read(w, r)
	if b == nil {
		return false
	}
	defer buffer.Put(b)

	if err := json.NewDecoder(b).Decode(v); err != nil {
		err = fmt.Errorf("error decoding json: %w", err)

		render.BadRequest(w, err)

		return false
	}

	return true
}

// AdminJSON is obsolete; it's here for backwards compatibility.
//
// Please don't use.
func AdminJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	b := read(w, r)
	if b == nil {
		return false
	}
	defer buffer.Put(b)

	if err := json.NewDecoder(b).Decode(v); err != nil {
		e := admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body")
		admin.WriteError(w, e)

		return false
	}

	return true
}

// ProtoJSON reads JSON from the request body and stores it in the value
// pointed by v.
func ProtoJSON(w http.ResponseWriter, r *http.Request, m proto.Message) bool {
	b := read(w, r)
	if b == nil {
		return false
	}
	defer buffer.Put(b)

	if err := protojson.Unmarshal(b.Bytes(), m); err != nil {
		err = fmt.Errorf("error decoding proto json: %w", err)

		render.BadRequest(w, err)

		return false
	}

	return true
}

func read(w http.ResponseWriter, r *http.Request) *bytes.Buffer {
	b := buffer.Get()
	if _, err := b.ReadFrom(r.Body); err != nil {
		buffer.Put(b)

		err = fmt.Errorf("error reading request body: %w", err)

		render.BadRequest(w, err)

		return nil
	}

	return b
}
