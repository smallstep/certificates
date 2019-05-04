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
	GetTokenID(token string) (string, error)
	GetName() string
	GetType() Type
	GetEncryptedKey() (kid string, key string, ok bool)
	Init(config Config) error
	AuthorizeSign(token string) ([]SignOption, error)
	AuthorizeRenewal(cert *x509.Certificate) error
	AuthorizeRevoke(token string) error
}

// Audiences stores all supported audiences by request type.
type Audiences struct {
	Sign   []string
	Revoke []string
}

// All returns all supported audiences across all request types in one list.
func (a *Audiences) All() []string {
	return append(a.Sign, a.Revoke...)
}

// Type indicates the provisioner Type.
type Type int

const (
	noopType Type = 0
	// TypeJWK is used to indicate the JWK provisioners.
	TypeJWK Type = 1
	// TypeOIDC is used to indicate the OIDC provisioners.
	TypeOIDC Type = 2
	// TypeGCP is used to indicate the GCP provisioners.
	TypeGCP Type = 3
	// TypeAWS is used to indicate the AWS provisioners.
	TypeAWS Type = 4
	// TypeAzure is used to indicate the Azure provisioners.
	TypeAzure Type = 5

	// RevokeAudienceKey is the key for the 'revoke' audiences in the audiences map.
	RevokeAudienceKey = "revoke"
	// SignAudienceKey is the key for the 'sign' audiences in the audiences map.
	SignAudienceKey = "sign"
)

// Config defines the default parameters used in the initialization of
// provisioners.
type Config struct {
	// Claims are the default claims.
	Claims Claims
	// Audiences are the audiences used in the default provisioner, (JWK).
	Audiences Audiences
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
		case "gcp":
			p = &GCP{}
		case "aws":
			p = &AWS{}
		case "azure":
			p = &Azure{}
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
