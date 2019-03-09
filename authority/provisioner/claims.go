package provisioner

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

// Claims so that individual provisioners can override global claims.
type Claims struct {
	globalClaims   *Claims
	MinTLSDur      *Duration `json:"minTLSCertDuration,omitempty"`
	MaxTLSDur      *Duration `json:"maxTLSCertDuration,omitempty"`
	DefaultTLSDur  *Duration `json:"defaultTLSCertDuration,omitempty"`
	DisableRenewal *bool     `json:"disableRenewal,omitempty"`
}

// Init initializes and validates the individual provisioner claims.
func (pc *Claims) Init(global *Claims) (*Claims, error) {
	if pc == nil {
		pc = &Claims{}
	}
	pc.globalClaims = global
	return pc, pc.Validate()
}

// DefaultTLSCertDuration returns the default TLS cert duration for the
// provisioner. If the default is not set within the provisioner, then the global
// default from the authority configuration will be used.
func (pc *Claims) DefaultTLSCertDuration() time.Duration {
	if pc.DefaultTLSDur == nil || pc.DefaultTLSDur.Duration == 0 {
		return pc.globalClaims.DefaultTLSCertDuration()
	}
	return pc.DefaultTLSDur.Duration
}

// MinTLSCertDuration returns the minimum TLS cert duration for the provisioner.
// If the minimum is not set within the provisioner, then the global
// minimum from the authority configuration will be used.
func (pc *Claims) MinTLSCertDuration() time.Duration {
	if pc.MinTLSDur == nil || pc.MinTLSDur.Duration == 0 {
		return pc.globalClaims.MinTLSCertDuration()
	}
	return pc.MinTLSDur.Duration
}

// MaxTLSCertDuration returns the maximum TLS cert duration for the provisioner.
// If the maximum is not set within the provisioner, then the global
// maximum from the authority configuration will be used.
func (pc *Claims) MaxTLSCertDuration() time.Duration {
	if pc.MaxTLSDur == nil || pc.MaxTLSDur.Duration == 0 {
		return pc.globalClaims.MaxTLSCertDuration()
	}
	return pc.MaxTLSDur.Duration
}

// IsDisableRenewal returns if the renewal flow is disabled for the
// provisioner. If the property is not set within the provisioner, then the
// global value from the authority configuration will be used.
func (pc *Claims) IsDisableRenewal() bool {
	if pc.DisableRenewal == nil {
		return pc.globalClaims.IsDisableRenewal()
	}
	return *pc.DisableRenewal
}

// Validate validates and modifies the Claims with default values.
func (pc *Claims) Validate() error {
	var (
		min = pc.MinTLSCertDuration()
		max = pc.MaxTLSCertDuration()
		def = pc.DefaultTLSCertDuration()
	)
	switch {
	case min == 0:
		return errors.Errorf("claims: MinTLSCertDuration cannot be empty")
	case max == 0:
		return errors.Errorf("claims: MaxTLSCertDuration cannot be empty")
	case def == 0:
		return errors.Errorf("claims: DefaultTLSCertDuration cannot be empty")
	case max < min:
		return errors.Errorf("claims: MaxCertDuration cannot be less "+
			"than MinCertDuration: MaxCertDuration - %v, MinCertDuration - %v", max, min)
	case def < min:
		return errors.Errorf("claims: DefaultCertDuration cannot be less than MinCertDuration: DefaultCertDuration - %v, MinCertDuration - %v", def, min)
	case max < def:
		return errors.Errorf("claims: MaxCertDuration cannot be less than DefaultCertDuration: MaxCertDuration - %v, DefaultCertDuration - %v", max, def)
	default:
		return nil
	}
}

// Duration is a wrapper around Time.Duration to aid with marshal/unmarshal.
type Duration struct {
	time.Duration
}

// MarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// UnmarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *Duration) UnmarshalJSON(data []byte) (err error) {
	var (
		s  string
		_d time.Duration
	)
	if d == nil {
		return errors.New("duration cannot be nil")
	}
	if err = json.Unmarshal(data, &s); err != nil {
		return errors.Wrapf(err, "error unmarshaling %s", data)
	}
	if _d, err = time.ParseDuration(s); err != nil {
		return errors.Wrapf(err, "error parsing %s as duration", s)
	}
	d.Duration = _d
	return
}
