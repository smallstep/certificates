// Package cmw parses RATS Conceptual Message Wrappers (CMW), defined in RFC
// 9999, in their record form, in JSON or in CBOR.
//
// Not supported: collections, CBOR records whose type is a CoAP content-format
// number, and the CBOR tag form, all of which return an error.
package cmw

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Indicator is the optional bit set of a record that says which kinds of
// conceptual message its value carries.
type Indicator uint

// The indicator bits, from the RATS Conceptual Message Wrapper (CMW)
// Indicators registry.
const (
	ReferenceValues Indicator = 1 << iota
	Endorsements
	Evidence
	AttestationResults
	AppraisalPolicy
)

// Has reports whether all the bits of b are set in i.
func (i Indicator) Has(b Indicator) bool {
	return i&b == b
}

// Record is a CMW record: a conceptual message and its media type.
type Record struct {
	// MediaType is the media type of the value, with its parameters.
	MediaType string
	// Value is the conceptual message.
	Value []byte
	// Indicator is the record's indicator, or 0 if it has none.
	Indicator Indicator
}

// Parse parses a CMW record in JSON, an array whose first byte is '[', or in
// CBOR.
func Parse(data []byte) (*Record, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("cmw is empty")
	}
	switch trimmed[0] {
	case '[':
		return parseJSON(trimmed)
	case '{':
		return nil, errors.New("cmw collections are not supported")
	}

	// The CBOR major type is in the top three bits of the first byte.
	switch data[0] >> 5 {
	case 4: // array
		return parseCBOR(data)
	case 5: // map
		return nil, errors.New("cmw collections are not supported")
	case 6: // tag
		return nil, errors.New("the cmw cbor tag form is not supported")
	default:
		return nil, errors.New("cmw is neither a json nor a cbor record")
	}
}

func parseJSON(data []byte) (*Record, error) {
	var fields []json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("error parsing cmw json record: %w", err)
	}
	if n := len(fields); n != 2 && n != 3 {
		return nil, fmt.Errorf("cmw json record must have 2 or 3 elements, it has %d", n)
	}

	var r Record
	if err := json.Unmarshal(fields[0], &r.MediaType); err != nil {
		return nil, fmt.Errorf("cmw json record type must be a media type string: %w", err)
	}
	var value string
	if err := json.Unmarshal(fields[1], &value); err != nil {
		return nil, fmt.Errorf("cmw json record value must be a base64url string: %w", err)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil {
		return nil, fmt.Errorf("cmw json record value must be a base64url string: %w", err)
	}
	r.Value = b
	if len(fields) == 3 {
		if err := json.Unmarshal(fields[2], &r.Indicator); err != nil {
			return nil, fmt.Errorf("cmw json record indicator must be an unsigned integer: %w", err)
		}
	}
	return r.validate()
}

func parseCBOR(data []byte) (*Record, error) {
	var fields []cbor.RawMessage
	if err := cbor.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("error parsing cmw cbor record: %w", err)
	}
	if n := len(fields); n != 2 && n != 3 {
		return nil, fmt.Errorf("cmw cbor record must have 2 or 3 elements, it has %d", n)
	}

	var r Record
	if err := cbor.Unmarshal(fields[0], &r.MediaType); err != nil {
		var cf uint
		if cbor.Unmarshal(fields[0], &cf) == nil {
			return nil, errors.New("cmw cbor records typed by a coap content-format are not supported")
		}
		return nil, fmt.Errorf("cmw cbor record type must be a media type string: %w", err)
	}
	if err := cbor.Unmarshal(fields[1], &r.Value); err != nil {
		return nil, fmt.Errorf("cmw cbor record value must be a byte string: %w", err)
	}
	if len(fields) == 3 {
		if err := cbor.Unmarshal(fields[2], &r.Indicator); err != nil {
			return nil, fmt.Errorf("cmw cbor record indicator must be an unsigned integer: %w", err)
		}
	}
	return r.validate()
}

func (r *Record) validate() (*Record, error) {
	if r.MediaType == "" {
		return nil, errors.New("cmw record type is empty")
	}
	if len(r.Value) == 0 {
		return nil, errors.New("cmw record value is empty")
	}
	return r, nil
}
