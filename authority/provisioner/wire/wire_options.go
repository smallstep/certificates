package wire

import (
	"errors"
	"fmt"
	"sync"
)

// Options holds the Wire ACME extension options
type Options struct {
	OIDC *OIDCOptions `json:"oidc,omitempty"`
	DPOP *DPOPOptions `json:"dpop,omitempty"`

	validateOnce  sync.Once
	validationErr error
}

// GetOIDCOptions returns the OIDC options.
func (o *Options) GetOIDCOptions() *OIDCOptions {
	if o == nil {
		return nil
	}
	return o.OIDC
}

// GetDPOPOptions returns the DPoP options.
func (o *Options) GetDPOPOptions() *DPOPOptions {
	if o == nil {
		return nil
	}
	return o.DPOP
}

func (o *Options) Validate() error {
	o.validateOnce.Do(
		func() {
			o.validationErr = validate(o)
		},
	)

	return o.validationErr
}

func validate(o *Options) error {
	if oidc := o.GetOIDCOptions(); oidc != nil {
		if err := oidc.validate(); err != nil {
			return fmt.Errorf("failed validating OIDC options: %w", err)
		}
	} else {
		return errors.New("no OIDC options available")
	}

	if dpop := o.GetDPOPOptions(); dpop != nil {
		if err := dpop.validate(); err != nil {
			return fmt.Errorf("failed validating DPoP options: %w", err)
		}
	} else {
		return errors.New("no DPoP options available")
	}

	return nil
}
