package apiv1

import (
	"context"
	"sync"
)

var registry = new(sync.Map)

// KeyManagerNewFunc is the type that represents the method to initialize a new
// KeyManager.
type KeyManagerNewFunc func(ctx context.Context, opts Options) (KeyManager, error)

// Register adds to the registry a method to create a KeyManager of type t.
func Register(t Type, fn KeyManagerNewFunc) {
	registry.Store(t, fn)
}

// LoadKeyManagerNewFunc returns the function initialize a KayManager.
func LoadKeyManagerNewFunc(t Type) (KeyManagerNewFunc, bool) {
	v, ok := registry.Load(t)
	if !ok {
		return nil, false
	}
	fn, ok := v.(KeyManagerNewFunc)
	return fn, ok
}
