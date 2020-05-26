package uri

import (
	"net/url"
	"strings"

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
	return u.Values.Get(key)
}
