package wire

import (
	"errors"
	"fmt"
)

// Options holds the Wire ACME extension options
type Options struct {
	OIDC *OIDCOptions `json:"oidc,omitempty"`
	DPOP *DPOPOptions `json:"dpop,omitempty"`
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

// Validate validates and initializes the Wire OIDC and DPoP options.
//
// TODO(hs): find a good way to perform this only once.
func (o *Options) Validate() error {
	if oidc := o.GetOIDCOptions(); oidc != nil {
		if err := oidc.validateAndInitialize(); err != nil {
			return fmt.Errorf("failed initializing OIDC options: %w", err)
		}
	} else {
		return errors.New("no OIDC options available")
	}

	if dpop := o.GetDPOPOptions(); dpop != nil {
		if err := dpop.validateAndInitialize(); err != nil {
			return fmt.Errorf("failed initializing DPoP options: %w", err)
		}
	} else {
		return errors.New("no DPoP options available")
	}

	return nil
}
