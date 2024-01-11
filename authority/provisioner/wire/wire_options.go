package wire

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

// GetDPOPOptions returns the OIDC options.
func (o *Options) GetDPOPOptions() *DPOPOptions {
	if o == nil {
		return nil
	}
	return o.DPOP
}
