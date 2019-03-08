package provisioner

import (
	"crypto/x509"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

// Interface is the interface that all provisioner types must implement.
type Interface interface {
	GetID() string
	GetName() string
	GetType() Type
	GetEncryptedKey() (kid string, key string, ok bool)
	Init(config Config) error
	Authorize(token string) ([]SignOption, error)
	AuthorizeRenewal(cert *x509.Certificate) error
	AuthorizeRevoke(token string) error
}

// Type indicates the provisioner Type.
type Type int

const (
	noopType Type = 0

	// TypeJWK is used to indicate the JWK provisioners.
	TypeJWK Type = 1

	// TypeOIDC is used to indicate the OIDC provisioners.
	TypeOIDC Type = 2
)

// Config defines the default parameters used in the initialization of
// provisioners.
type Config struct {
	// Claims are the default claims.
	Claims Claims
	// Audiences are the audiences used in the default provisioner, (JWK).
	Audiences []string
}

type provisioner struct {
	Type string `json:"type"`
}

// List represents a list of provisioners.
type List []Interface

// UnmarshalJSON implements json.Unmarshaler and allows to unmarshal a list of a
// interfaces into the right type.
func (l *List) UnmarshalJSON(data []byte) error {
	ps := []json.RawMessage{}
	if err := json.Unmarshal(data, &ps); err != nil {
		return errors.Wrap(err, "error unmarshaling provisioner list")
	}

	*l = List{}
	for _, data := range ps {
		var typ provisioner
		if err := json.Unmarshal(data, &typ); err != nil {
			return errors.Errorf("error unmarshaling provisioner")
		}
		var p Interface
		switch strings.ToLower(typ.Type) {
		case "jwk":
			p = &JWK{}
		case "oidc":
			p = &OIDC{}
		default:
			return errors.Errorf("provisioner type %s not supported", typ.Type)
		}
		if err := json.Unmarshal(data, p); err != nil {
			return errors.Errorf("error unmarshaling provisioner")
		}
		*l = append(*l, p)
	}

	return nil
}
