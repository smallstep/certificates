package sshutil

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// Hosts are tagged with k,v pairs. These tags are how a user is ultimately
// associated with a host.
type HostTag struct {
	ID    string
	Name  string
	Value string
}

// Host defines expected attributes for an ssh host.
type Host struct {
	HostID   string    `json:"hid"`
	HostTags []HostTag `json:"host_tags"`
	Hostname string    `json:"hostname"`
}

// CertType defines the certificate type, it can be a user or a host
// certificate.
type CertType uint32

const (
	// UserCert defines a user certificate.
	UserCert CertType = ssh.UserCert

	// HostCert defines a host certificate.
	HostCert CertType = ssh.HostCert
)

const (
	userString = "user"
	hostString = "host"
)

// String returns "user" for user certificates and "host" for host certificates.
// It will return the empty string for any other value.
func (c CertType) String() string {
	switch c {
	case UserCert:
		return userString
	case HostCert:
		return hostString
	default:
		return ""
	}
}

// MarshalJSON implements the json.Marshaler interface for CertType. UserCert
// will be marshaled as the string "user" and HostCert as "host".
func (c CertType) MarshalJSON() ([]byte, error) {
	if s := c.String(); s != "" {
		return []byte(`"` + s + `"`), nil
	}
	return nil, errors.Errorf("unknown certificate type %d", c)
}

// UnmarshalJSON implements the json.Unmarshaler interface for CertType.
func (c *CertType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error unmarshaling certificate type")
	}
	switch strings.ToLower(s) {
	case userString:
		*c = UserCert
		return nil
	case hostString:
		*c = HostCert
		return nil
	default:
		return errors.Errorf("error unmarshaling '%s' as a certificate type", s)
	}
}
