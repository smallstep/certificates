package x509util

import (
	"encoding/asn1"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// MultiString is a type used to unmarshal a JSON string or an array of strings
// into a []string.
type MultiString []string

// UnmarshalJSON implements the json.Unmarshaler interface for MultiString.
func (m *MultiString) UnmarshalJSON(data []byte) error {
	if s, ok := maybeString(data); ok {
		*m = MultiString([]string{s})
		return nil
	}

	var v []string
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*m = MultiString(v)
	return nil
}

// MultiIP is a type used to unmarshal a JSON string or an array of strings into
// a []net.IP.
type MultiIP []net.IP

// UnmarshalJSON implements the json.Unmarshaler interface for MultiIP.
func (m *MultiIP) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	if ms != nil {
		ips := make([]net.IP, len(ms))
		for i, s := range ms {
			ip := net.ParseIP(s)
			if ip == nil {
				return errors.Errorf("error unmarshaling json: ip %s is not valid", s)
			}
			ips[i] = ip
		}

		*m = MultiIP(ips)
	}
	return nil
}

// MultiIPNet is a type used to unmarshal a JSON string or an array of strings
// into a []*net.IPNet.
type MultiIPNet []*net.IPNet

// MarshalJSON implements the json.Marshaler interface for MultiIPNet.
func (m MultiIPNet) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	ipNets := make([]string, len(m))
	for i, v := range m {
		ipNets[i] = v.String()
	}
	return json.Marshal(ipNets)
}

// UnmarshalJSON implements the json.Unmarshaler interface for MultiIPNet.
func (m *MultiIPNet) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	if ms != nil {
		ipNets := make([]*net.IPNet, len(ms))
		for i, s := range ms {
			_, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				return errors.Wrap(err, "error unmarshaling json")
			}
			ipNets[i] = ipNet
		}

		*m = MultiIPNet(ipNets)
	}
	return nil
}

// MultiURL is a type used to unmarshal a JSON string or an array of strings
// into a []*url.URL.
type MultiURL []*url.URL

// MarshalJSON implements the json.Marshaler interface for MultiURL.
func (m MultiURL) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	urls := make([]string, len(m))
	for i, u := range m {
		urls[i] = u.String()
	}
	return json.Marshal(urls)
}

// UnmarshalJSON implements the json.Unmarshaler interface for MultiURL.
func (m *MultiURL) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	if ms != nil {
		urls := make([]*url.URL, len(ms))
		for i, s := range ms {
			u, err := url.Parse(s)
			if err != nil {
				return errors.Wrap(err, "error unmarshaling json")
			}
			urls[i] = u
		}

		*m = MultiURL(urls)
	}
	return nil
}

// MultiObjectIdentifier is a type used to unmarshal a JSON string or an array
// of strings into a []asn1.ObjectIdentifier.
type MultiObjectIdentifier []asn1.ObjectIdentifier

// MarshalJSON implements the json.Marshaler interface for MultiObjectIdentifier.
func (m MultiObjectIdentifier) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	oids := make([]string, len(m))
	for i, u := range m {
		oids[i] = u.String()
	}
	return json.Marshal(oids)
}

// UnmarshalJSON implements the json.Unmarshaler interface for
// MultiObjectIdentifier.
func (m *MultiObjectIdentifier) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	if ms != nil {
		oids := make([]asn1.ObjectIdentifier, len(ms))
		for i, s := range ms {
			oid, err := parseObjectIdentifier(s)
			if err != nil {
				return err
			}
			oids[i] = oid
		}

		*m = MultiObjectIdentifier(oids)
	}
	return nil
}

func maybeString(data []byte) (string, bool) {
	if len(data) > 0 && data[0] == '"' {
		var v string
		if err := json.Unmarshal(data, &v); err == nil {
			return v, true
		}
	}
	return "", false
}

func unmarshalString(data []byte) (string, error) {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return v, errors.Wrap(err, "error unmarshaling json")
	}
	return v, nil
}

func unmarshalMultiString(data []byte) ([]string, error) {
	var v MultiString
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling json")
	}
	return []string(v), nil
}

func parseObjectIdentifier(oid string) (asn1.ObjectIdentifier, error) {
	if oid == "" {
		return asn1.ObjectIdentifier{}, nil
	}

	parts := strings.Split(oid, ".")
	oids := make([]int, len(parts))

	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil {
			return asn1.ObjectIdentifier{}, errors.Errorf("error unmarshaling json: %s is not an ASN1 object identifier", oid)
		}
		oids[i] = n
	}
	return asn1.ObjectIdentifier(oids), nil
}
