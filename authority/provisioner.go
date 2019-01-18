package authority

import (
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"

	jose "gopkg.in/square/go-jose.v2"
)

// ProvisionerClaims so that individual provisioners can override global claims.
type ProvisionerClaims struct {
	globalClaims   *ProvisionerClaims
	MinTLSDur      *duration `json:"minTLSCertDuration,omitempty"`
	MaxTLSDur      *duration `json:"maxTLSCertDuration,omitempty"`
	DefaultTLSDur  *duration `json:"defaultTLSCertDuration,omitempty"`
	DisableRenewal *bool     `json:"disableRenewal,omitempty"`
}

// Init initializes and validates the individual provisioner claims.
func (pc *ProvisionerClaims) Init(global *ProvisionerClaims) (*ProvisionerClaims, error) {
	if pc == nil {
		pc = &ProvisionerClaims{}
	}
	pc.globalClaims = global
	err := pc.Validate()
	return pc, err
}

// DefaultTLSCertDuration returns the default TLS cert duration for the
// provisioner. If the default is not set within the provisioner, then the global
// default from the authority configuration will be used.
func (pc *ProvisionerClaims) DefaultTLSCertDuration() time.Duration {
	if pc.DefaultTLSDur == nil || *pc.DefaultTLSDur == 0 {
		return pc.globalClaims.DefaultTLSCertDuration()
	}
	return time.Duration(*pc.DefaultTLSDur)
}

// MinTLSCertDuration returns the minimum TLS cert duration for the provisioner.
// If the minimum is not set within the provisioner, then the global
// minimum from the authority configuration will be used.
func (pc *ProvisionerClaims) MinTLSCertDuration() time.Duration {
	if pc.MinTLSDur == nil || *pc.MinTLSDur == 0 {
		return pc.globalClaims.MinTLSCertDuration()
	}
	return time.Duration(*pc.MinTLSDur)
}

// MaxTLSCertDuration returns the maximum TLS cert duration for the provisioner.
// If the maximum is not set within the provisioner, then the global
// maximum from the authority configuration will be used.
func (pc *ProvisionerClaims) MaxTLSCertDuration() time.Duration {
	if pc.MaxTLSDur == nil || *pc.MaxTLSDur == 0 {
		return pc.globalClaims.MaxTLSCertDuration()
	}
	return time.Duration(*pc.MaxTLSDur)
}

// IsDisableRenewal returns if the renewal flow is disabled for the
// provisioner. If the property is not set within the provisioner, then the
// global value from the authority configuration will be used.
func (pc *ProvisionerClaims) IsDisableRenewal() bool {
	if pc.DisableRenewal == nil {
		return pc.globalClaims.IsDisableRenewal()
	}
	return *pc.DisableRenewal
}

// Validate validates and modifies the Claims with default values.
func (pc *ProvisionerClaims) Validate() error {
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

// Provisioner - authorized entity that can sign tokens necessary for signature requests.
type Provisioner struct {
	Name         string             `json:"name,omitempty"`
	Type         string             `json:"type,omitempty"`
	Key          *jose.JSONWebKey   `json:"key,omitempty"`
	EncryptedKey string             `json:"encryptedKey,omitempty"`
	Claims       *ProvisionerClaims `json:"claims,omitempty"`
}

// Init initializes and validates a the fields of Provisioner type.
func (p *Provisioner) Init(global *ProvisionerClaims) error {
	switch {
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")

	case p.Type == "":
		return errors.New("provisioner type cannot be empty")

	case p.Key == nil:
		return errors.New("provisioner key cannot be empty")
	}

	var err error
	p.Claims, err = p.Claims.Init(global)
	return err
}

// getTLSApps returns a list of modifiers and validators that will be applied to
// the certificate.
func (p *Provisioner) getTLSApps(so SignOptions) ([]x509util.WithOption, []certClaim, error) {
	c := p.Claims
	return []x509util.WithOption{
			x509util.WithNotBeforeAfterDuration(so.NotBefore,
				so.NotAfter, c.DefaultTLSCertDuration()),
			withProvisionerOID(p.Name, p.Key.KeyID),
		}, []certClaim{
			&certTemporalClaim{
				min: c.MinTLSCertDuration(),
				max: c.MaxTLSCertDuration(),
			},
		}, nil
}

// ID returns the provisioner identifier. The name and credential id should
// uniquely identify any provisioner.
func (p *Provisioner) ID() string {
	return p.Name + ":" + p.Key.KeyID
}
