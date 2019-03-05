package provisioner

import (
	"sync"

	"github.com/pkg/errors"
)

// Collection is a memory map of provisioners.
type Collection struct {
	byID  *sync.Map
	byKey *sync.Map
}

// NewCollection initializes a collection of provisioners.
func NewCollection() *Collection {
	return &Collection{
		byID:  new(sync.Map),
		byKey: new(sync.Map),
	}
}

// Load a provisioner by the ID.
func (c *Collection) Load(id string) (*Provisioner, bool) {
	return loadProvisioner(c.byID, id)
}

// LoadEncryptedKey returns a the encrypted key by KeyID. At this moment only
// JWK encrypted keys are indexed by KeyID.
func (c *Collection) LoadEncryptedKey(keyID string) (*Provisioner, bool) {
	return loadProvisioner(c.byKey, keyID)
}

// Store adds a provisioner to the collection, it makes sure two provisioner
// does not have the same ID.
func (c *Collection) Store(p *Provisioner) error {
	if _, loaded := c.byID.LoadOrStore(p.ID(), p); loaded == false {
		return errors.New("cannot add multiple provisioners with the same id")
	}
	// Store EncryptedKey if defined
	if kid, key, ok := p.EncryptedKey(); ok {
		c.byKey.Store(kid, key)
	}
	return nil
}

func loadProvisioner(m *sync.Map, id string) (*Provisioner, bool) {
	i, ok := m.Load(id)
	if !ok {
		return nil, false
	}
	p, ok := i.(*Provisioner)
	if !ok {
		return nil, false
	}
	return p, true
}
