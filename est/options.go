package est

import (
	"crypto/x509"
	"errors"
)

// Options configures the EST authority instance.
type Options struct {
	Roots         []*x509.Certificate `json:"-"`
	Intermediates []*x509.Certificate `json:"-"`
}

// Validate checks the fields in Options.
func (o *Options) Validate() error {
	switch {
	case len(o.Roots) == 0:
		return errors.New("no root certificate available for EST authority")
	case len(o.Intermediates) == 0:
		return errors.New("no intermediate certificate available for EST authority")
	}

	return nil
}
