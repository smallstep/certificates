package uri

import (
	"bytes"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// URI implements a parser for a URI format based on the the PKCS #11 URI Scheme
// defined in https://tools.ietf.org/html/rfc7512
//
// These URIs will be used to define the key names in a KMS.
type URI struct {
	*url.URL
	Values url.Values
}

// New creates a new URI from a scheme and key-value pairs.
func New(scheme string, values url.Values) *URI {
	return &URI{
		URL: &url.URL{
			Scheme: scheme,
			Opaque: strings.ReplaceAll(values.Encode(), "&", ";"),
		},
		Values: values,
	}
}

// NewFile creates an uri for a file.
func NewFile(path string) *URI {
	return &URI{
		URL: &url.URL{
			Scheme: "file",
			Path:   path,
		},
	}
}

// HasScheme returns true if the given uri has the given scheme, false otherwise.
func HasScheme(scheme, rawuri string) bool {
	u, err := url.Parse(rawuri)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, scheme)
}

// Parse returns the URI for the given string or an error.
func Parse(rawuri string) (*URI, error) {
	u, err := url.Parse(rawuri)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", rawuri)
	}
	if u.Scheme == "" {
		return nil, errors.Errorf("error parsing %s: scheme is missing", rawuri)
	}
	// Starting with Go 1.17 url.ParseQuery returns an error using semicolon as
	// separator.
	v, err := url.ParseQuery(strings.ReplaceAll(u.Opaque, ";", "&"))
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", rawuri)
	}

	return &URI{
		URL:    u,
		Values: v,
	}, nil
}

// ParseWithScheme returns the URI for the given string only if it has the given
// scheme.
func ParseWithScheme(scheme, rawuri string) (*URI, error) {
	u, err := Parse(rawuri)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return nil, errors.Errorf("error parsing %s: scheme not expected", rawuri)
	}
	return u, nil
}

// Get returns the first value in the uri with the given key, it will return
// empty string if that field is not present.
func (u *URI) Get(key string) string {
	v := u.Values.Get(key)
	if v == "" {
		v = u.URL.Query().Get(key)
	}
	return v
}

// GetBool returns true if a given key has the value "true". It returns false
// otherwise.
func (u *URI) GetBool(key string) bool {
	v := u.Values.Get(key)
	if v == "" {
		v = u.URL.Query().Get(key)
	}
	return strings.EqualFold(v, "true")
}

// GetEncoded returns the first value in the uri with the given key, it will
// return empty nil if that field is not present or is empty. If the return
// value is hex encoded it will decode it and return it.
func (u *URI) GetEncoded(key string) []byte {
	v := u.Get(key)
	if v == "" {
		return nil
	}
	if len(v)%2 == 0 {
		if b, err := hex.DecodeString(v); err == nil {
			return b
		}
	}
	return []byte(v)
}

// Pin returns the pin encoded in the url. It will read the pin from the
// pin-value or the pin-source attributes.
func (u *URI) Pin() string {
	if value := u.Get("pin-value"); value != "" {
		return value
	}
	if path := u.Get("pin-source"); path != "" {
		if b, err := readFile(path); err == nil {
			return string(bytes.TrimRightFunc(b, unicode.IsSpace))
		}
	}
	return ""
}

func readFile(path string) ([]byte, error) {
	u, err := url.Parse(path)
	if err == nil && (u.Scheme == "" || u.Scheme == "file") && u.Path != "" {
		path = u.Path
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", path)
	}
	return b, nil
}
