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
	Init(claims *Claims) error
	Authorize(token string) ([]SignOption, error)
	AuthorizeRenewal(cert *x509.Certificate) error
	AuthorizeRevoke(token string) error
}

// Type indicates the provisioner Type.
type Type int

const (
	// TypeJWK is used to indicate the JWK provisioners.
	TypeJWK Type = 1

	// TypeOIDC is used to indicate the OIDC provisioners.
	TypeOIDC Type = 2
)

type provisioner struct {
	Type string `json:"type"`
}

// Provisioner implmements the provisioner.Interface on a base provisioner. It
// also implements custom marshalers and unmarshalers so different provisioners
// can be represented in a configuration type.
type Provisioner struct {
	base Interface
}

// New creates a new provisioner from the base provisioner.
func New(base Interface) *Provisioner {
	return &Provisioner{
		base: base,
	}
}

// Base returns the base type of the provisioner.
func (p *Provisioner) Base() Interface {
	return p.base
}

// GetID returns the base provisioner unique ID. This identifier is used as the
// key in a provisioner.Collection.
func (p *Provisioner) GetID() string {
	return p.base.GetID()
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *Provisioner) GetEncryptedKey() (string, string, bool) {
	return p.base.GetEncryptedKey()
}

// GetName returns the name of the provisioner
func (p *Provisioner) GetName() string {
	return p.base.GetName()
}

// GetType return the provisioners type.
func (p *Provisioner) GetType() Type {
	return p.base.GetType()
}

// Init initializes the base provisioner with the given claims.
func (p *Provisioner) Init(claims *Claims) error {
	return p.base.Init(claims)
}

// Authorize validates the given token on the base provisioner returning a list
// of options to validate the signing request.
func (p *Provisioner) Authorize(token string) ([]SignOption, error) {
	return p.base.Authorize(token)
}

// AuthorizeRenewal checks if the base provisioner authorizes the renewal.
func (p *Provisioner) AuthorizeRenewal(cert *x509.Certificate) error {
	return p.base.AuthorizeRenewal(cert)
}

// AuthorizeRevoke checks on the base provisioner if the given token has revoke
// access.
func (p *Provisioner) AuthorizeRevoke(token string) error {
	return p.base.AuthorizeRevoke(token)
}

// MarshalJSON implements the json.Marshaler interface on the Provisioner type.
func (p *Provisioner) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.base)
}

// UnmarshalJSON implements the json.Unmarshaler interface on the Provisioner
// type.
func (p *Provisioner) UnmarshalJSON(data []byte) error {
	var typ provisioner
	if err := json.Unmarshal(data, &typ); err != nil {
		return errors.Errorf("error unmarshalling provisioner")
	}

	switch strings.ToLower(typ.Type) {
	case "jwk":
		p.base = &JWT{}
	case "oidc":
		p.base = &OIDC{}
	default:
		return errors.Errorf("provisioner type %s not supported", typ.Type)
	}
	if err := json.Unmarshal(data, &p.base); err != nil {
		return errors.Errorf("error unmarshalling provisioner")
	}
	return nil
}
