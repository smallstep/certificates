package authority

// Capabilities defines the capabilities of the authority.
type Capabilities struct {
	RemoteConfigurationManagement bool `json:"remoteConfigurationManagement,omitempty"`
	RequireClientAuthentication   bool `json:"requireClientAuthentication,omitempty"`
}

// Capabilities returns the capabilities information of the authority.
func (a *Authority) Capabilities() Capabilities {
	return Capabilities{
		RemoteConfigurationManagement: a.config.AuthorityConfig.EnableAdmin,
		RequireClientAuthentication:   GlobalVersion.RequireClientAuthentication,
	}
}
