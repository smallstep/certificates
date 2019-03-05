package provisioner

import (
	"sync"

	"github.com/pkg/errors"
)

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
