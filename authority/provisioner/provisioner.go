package provisioner

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

// Interface is the interface that all provisioner types must implement.
type Interface interface {
	ID() string
	Init(claims *Claims) error
	Authorize(token string) ([]SignOption, error)
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
	typ  Type
	base Interface
}

// ID returns the base provisioner unique ID. This identifier is used as the key
// in a provisioner.Collection.
func (p *Provisioner) ID() string {
	return p.base.ID()
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
	case "jwt":
		p.base = &JWT{}
	case "oidc":
		p.base = &OIDC{}
	default:
		return errors.New("provisioner type not supported")
	}
	if err := json.Unmarshal(data, &p.base); err != nil {
		return errors.Errorf("error unmarshalling provisioner")
	}
	return nil
}

// Collection is a memory map of provisioners.
type Collection struct {
	byID *sync.Map
}

// NewCollection initializes a collection of provisioners.
func NewCollection() *Collection {
	return &Collection{
		byID: new(sync.Map),
	}
}

// Load a provisioner by the ID.
func (c *Collection) Load(id string) (*Provisioner, bool) {
	i, ok := c.byID.Load(id)
	if !ok {
		return nil, false
	}
	p, ok := i.(*Provisioner)
	if !ok {
		return nil, false
	}
	return p, true
}

// Store adds a provisioner to the collection, it makes sure two provisioner
// does not have the same ID.
func (c *Collection) Store(p *Provisioner) error {
	if _, loaded := c.byID.LoadOrStore(p.ID(), p); loaded == false {
		return errors.New("cannot add multiple provisioners with the same id")
	}
	return nil
}
