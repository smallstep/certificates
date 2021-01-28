package uri

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/url"
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
	v, err := url.ParseQuery(u.Opaque)
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

// Get returns the first value in the uri with the give n key, it will return
// empty string if that field is not present.
func (u *URI) Get(key string) string {
	v := u.Values.Get(key)
	if v == "" {
		v = u.URL.Query().Get(key)
	}
	return StringDecode(v)
}

// GetHex returns the first value in the uri with the give n key, it will return
// empty nil if that field is not present.
func (u *URI) GetHex(key string) ([]byte, error) {
	v := u.Values.Get(key)
	if v == "" {
		v = u.URL.Query().Get(key)
	}
	return HexDecode(v)
}

// Pin returns the pin encoded in the url. It will read the pin from the
// pin-value or the pin-source attributes.
func (u *URI) Pin() string {
	if value := u.Get("pin-value"); value != "" {
		return StringDecode(value)
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
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", path)
	}
	return b, nil
}

// PercentEncode encodes the given bytes using the percent encoding described in
// RFC3986 (https://tools.ietf.org/html/rfc3986).
func PercentEncode(b []byte) string {
	buf := new(strings.Builder)
	for _, v := range b {
		buf.WriteString("%" + hex.EncodeToString([]byte{v}))
	}
	return buf.String()
}

// PercentDecode decodes the given string using the percent encoding described
// in RFC3986 (https://tools.ietf.org/html/rfc3986).
func PercentDecode(s string) ([]byte, error) {
	if len(s)%3 != 0 {
		return nil, errors.Errorf("error parsing %s: wrong length", s)
	}

	var first string
	buf := new(bytes.Buffer)
	for i, r := range s {
		mod := i % 3
		rr := string(r)
		switch mod {
		case 0:
			if r != '%' {
				return nil, errors.Errorf("error parsing %s: expected %% and found %s in position %d", s, rr, i)
			}
		case 1:
			if !isHex(r) {
				return nil, errors.Errorf("error parsing %s: %s in position %d is not an hexadecimal number", s, rr, i)
			}
			first = string(r)
		case 2:
			if !isHex(r) {
				return nil, errors.Errorf("error parsing %s: %s in position %d is not an hexadecimal number", s, rr, i)
			}
			b, err := hex.DecodeString(first + rr)
			if err != nil {
				return nil, errors.Wrapf(err, "error parsing %s", s)
			}
			buf.Write(b)
		}
	}
	return buf.Bytes(), nil
}

// StringDecode returns the string given, but it will use Percent-Encoding if
// the string is percent encoded.
func StringDecode(s string) string {
	if strings.HasPrefix(s, "%") {
		if b, err := PercentDecode(s); err == nil {
			return string(b)
		}
	}
	return s
}

// HexDecode deocdes the string s using Percent-Encoding or regular hex
// encoding.
func HexDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	} else if strings.HasPrefix(s, "%") {
		return PercentDecode(s)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", s)
	}
	return b, nil
}

func isHex(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'a' && r <= 'f':
		return true
	case r >= 'A' && r <= 'F':
		return true
	default:
		return false
	}
}
