package provisioner

import "time"

// Claims so that individual provisioners can override global claims.
type Claims struct {
	globalClaims   *Claims
	MinTLSDur      *Duration `json:"minTLSCertDuration,omitempty"`
	MaxTLSDur      *Duration `json:"maxTLSCertDuration,omitempty"`
	DefaultTLSDur  *Duration `json:"defaultTLSCertDuration,omitempty"`
	DisableRenewal *bool     `json:"disableRenewal,omitempty"`
}

// Duration is a wrapper around Time.Duration to aid with marshal/unmarshal.
type Duration struct {
	time.Duration
}
