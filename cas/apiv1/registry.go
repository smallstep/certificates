package apiv1

import (
	"context"
	"sync"
)

var (
	registry = new(sync.Map)
)

// CertificateAuthorityServiceNewFunc is the type that represents the method to initialize a new
// CertificateAuthorityService.
type CertificateAuthorityServiceNewFunc func(ctx context.Context, opts Options) (CertificateAuthorityService, error)

// Register adds to the registry a method to create a KeyManager of type t.
func Register(t Type, fn CertificateAuthorityServiceNewFunc) {
	registry.Store(t.String(), fn)
}

// LoadCertificateAuthorityServiceNewFunc returns the function to initialize a KeyManager.
func LoadCertificateAuthorityServiceNewFunc(t Type) (CertificateAuthorityServiceNewFunc, bool) {
	v, ok := registry.Load(t.String())
	if !ok {
		return nil, false
	}
	fn, ok := v.(CertificateAuthorityServiceNewFunc)
	return fn, ok
}
