package authority

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

type duration struct {
	time.Duration
}

// MarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *duration) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return errors.Wrapf(err, "error unmarshalling %s", data)
	}
	if d.Duration, err = time.ParseDuration(s); err != nil {
		return errors.Wrapf(err, "error parsing %s as duration", s)
	}
	return
}

type multiString []string

// FIXME: remove me, avoids deadcode warning
var _ = multiString{}

// First returns the first element of a multiString. It will return an empty
// string if the multistring is empty.
func (s multiString) First() string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// Empties checks that none of the string is empty.
func (s multiString) Empties() bool {
	if len(s) == 0 {
		return true
	}
	for _, ss := range s {
		if len(ss) == 0 {
			return true
		}
	}
	return false
}

// MarshalJSON marshals the multistring as a string or a slice of strings . With
// 0 elements it will return the empty string, with 1 element a regular string,
// otherwise a slice of strings.
func (s multiString) MarshalJSON() ([]byte, error) {
	switch len(s) {
	case 0:
		return []byte(""), nil
	case 1:
		return json.Marshal(s[0])
	default:
		return json.Marshal(s)
	}
}

// UnmarshalJSON parses a string or a slice and sets it to the multiString.
func (s *multiString) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return errors.Wrapf(err, "error unmarshalling %s", data)
		}
		*s = []string{str}
		return nil
	}
	if err := json.Unmarshal(data, s); err != nil {
		return errors.Wrapf(err, "error unmarshalling %s", data)
	}
	return nil
}
