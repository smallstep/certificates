package mgmt

import (
	"github.com/smallstep/certificates/authority/config"
	authority "github.com/smallstep/certificates/authority/config"
)

const (
	DefaultAuthorityID = "00000000-0000-0000-0000-000000000000"
)

// StatusType is the type for status.
type StatusType int

const (
	// StatusActive active
	StatusActive StatusType = iota
	// StatusDeleted deleted
	StatusDeleted
)

type Claims struct {
	*X509Claims    `json:"x509Claims"`
	*SSHClaims     `json:"sshClaims"`
	DisableRenewal *bool `json:"disableRenewal"`
}

type X509Claims struct {
	Durations *Durations `json:"durations"`
}

type SSHClaims struct {
	UserDuration *Durations `json:"userDurations"`
	HostDuration *Durations `json:"hostDuration"`
}

type Durations struct {
	Min     string `json:"min"`
	Max     string `json:"max"`
	Default string `json:"default"`
}

// Admin type.
type Admin struct {
	ID           string     `json:"-"`
	AuthorityID  string     `json:"-"`
	Name         string     `json:"name"`
	Provisioner  string     `json:"provisioner"`
	IsSuperAdmin bool       `json:"isSuperAdmin"`
	Status       StatusType `json:"status"`
}

// Provisioner type.
type Provisioner struct {
	ID           string      `json:"-"`
	AuthorityID  string      `json:"-"`
	Type         string      `json:"type"`
	Name         string      `json:"name"`
	Claims       *Claims     `json:"claims"`
	Details      interface{} `json:"details"`
	X509Template string      `json:"x509Template"`
	SSHTemplate  string      `json:"sshTemplate"`
	Status       StatusType  `json:"status"`
}

// AuthConfig represents the Authority Configuration.
type AuthConfig struct {
	//*cas.Options         `json:"cas"`
	ID                   string         `json:"id"`
	ASN1DN               *config.ASN1DN `json:"template,omitempty"`
	Provisioners         []*Provisioner `json:"-"`
	Claims               *Claims        `json:"claims,omitempty"`
	DisableIssuedAtCheck bool           `json:"disableIssuedAtCheck,omitempty"`
	Backdate             string         `json:"backdate,omitempty"`
	Status               StatusType     `json:"status,omitempty"`
}

func (ac *AuthConfig) ToCertificates() (*config.AuthConfig, error) {
	return &authority.AuthConfig{}, nil
}

/*
// ToCertificates converts the landlord provisioner type to the open source
// provisioner type.
func (p *Provisioner) ToCertificates(ctx context.Context, db database.DB) (provisioner.Interface, error) {
	claims, err := p.Claims.ToCertificates()
	if err != nil {
		return nil, err
	}

	details := p.Details.GetData()
	if details == nil {
		return nil, fmt.Errorf("provisioner does not have any details")
	}

	options, err := p.getOptions(ctx, db)
	if err != nil {
		return nil, err
	}

	switch d := details.(type) {
	case *ProvisionerDetails_JWK:
		k := d.JWK.GetKey()
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(k.Key.Public, &jwk); err != nil {
			return nil, err
		}
		return &provisioner.JWK{
			Type:         p.Type.String(),
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: string(k.Key.Private),
			Claims:       claims,
			Options:      options,
		}, nil
	case *ProvisionerDetails_OIDC:
		cfg := d.OIDC
		return &provisioner.OIDC{
			Type:                  p.Type.String(),
			Name:                  p.Name,
			TenantID:              cfg.TenantId,
			ClientID:              cfg.ClientId,
			ClientSecret:          cfg.ClientSecret,
			ConfigurationEndpoint: cfg.ConfigurationEndpoint,
			Admins:                cfg.Admins,
			Domains:               cfg.Domains,
			Groups:                cfg.Groups,
			ListenAddress:         cfg.ListenAddress,
			Claims:                claims,
			Options:               options,
		}, nil
	case *ProvisionerDetails_GCP:
		cfg := d.GCP
		return &provisioner.GCP{
			Type:                   p.Type.String(),
			Name:                   p.Name,
			ServiceAccounts:        cfg.ServiceAccounts,
			ProjectIDs:             cfg.ProjectIds,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			InstanceAge:            durationValue(cfg.InstanceAge),
			Claims:                 claims,
			Options:                options,
		}, nil
	case *ProvisionerDetails_AWS:
		cfg := d.AWS
		return &provisioner.AWS{
			Type:                   p.Type.String(),
			Name:                   p.Name,
			Accounts:               cfg.Accounts,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			InstanceAge:            durationValue(cfg.InstanceAge),
			Claims:                 claims,
			Options:                options,
		}, nil
	case *ProvisionerDetails_Azure:
		cfg := d.Azure
		return &provisioner.Azure{
			Type:                   p.Type.String(),
			Name:                   p.Name,
			TenantID:               cfg.TenantId,
			ResourceGroups:         cfg.ResourceGroups,
			Audience:               cfg.Audience,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			Claims:                 claims,
			Options:                options,
		}, nil
	case *ProvisionerDetails_X5C:
		var roots []byte
		for i, k := range d.X5C.GetRoots() {
			if b := k.GetKey().GetPublic(); b != nil {
				if i > 0 {
					roots = append(roots, '\n')
				}
				roots = append(roots, b...)
			}
		}
		return &provisioner.X5C{
			Type:    p.Type.String(),
			Name:    p.Name,
			Roots:   roots,
			Claims:  claims,
			Options: options,
		}, nil
	case *ProvisionerDetails_K8SSA:
		var publicKeys []byte
		for i, k := range d.K8SSA.GetPublicKeys() {
			if b := k.GetKey().GetPublic(); b != nil {
				if i > 0 {
					publicKeys = append(publicKeys, '\n')
				}
				publicKeys = append(publicKeys, k.Key.Public...)
			}
		}
		return &provisioner.K8sSA{
			Type:    p.Type.String(),
			Name:    p.Name,
			PubKeys: publicKeys,
			Claims:  claims,
			Options: options,
		}, nil
	case *ProvisionerDetails_SSHPOP:
		return &provisioner.SSHPOP{
			Type:   p.Type.String(),
			Name:   p.Name,
			Claims: claims,
		}, nil
	case *ProvisionerDetails_ACME:
		cfg := d.ACME
		return &provisioner.ACME{
			Type:    p.Type.String(),
			Name:    p.Name,
			ForceCN: cfg.ForceCn,
			Claims:  claims,
			Options: options,
		}, nil
	default:
		return nil, fmt.Errorf("provisioner %s not implemented", p.Type.String())
	}
}

// ToCertificates converts the landlord provisioner claims type to the open source
// (step-ca) claims type.
func (c *Claims) ToCertificates() (*provisioner.Claims, error) {
	x509, ssh := c.GetX509(), c.GetSsh()
	x509Durations := x509.GetDurations()
	hostDurations := ssh.GetHostDurations()
	userDurations := ssh.GetUserDurations()
	enableSSHCA := ssh.GetEnabled()
	return &provisioner.Claims{
		MinTLSDur:         durationPtr(x509Durations.GetMin()),
		MaxTLSDur:         durationPtr(x509Durations.GetMax()),
		DefaultTLSDur:     durationPtr(x509Durations.GetDefault()),
		DisableRenewal:    &c.DisableRenewal,
		MinUserSSHDur:     durationPtr(userDurations.GetMin()),
		MaxUserSSHDur:     durationPtr(userDurations.GetMax()),
		DefaultUserSSHDur: durationPtr(userDurations.GetDefault()),
		MinHostSSHDur:     durationPtr(hostDurations.GetMin()),
		MaxHostSSHDur:     durationPtr(hostDurations.GetMax()),
		DefaultHostSSHDur: durationPtr(hostDurations.GetDefault()),
		EnableSSHCA:       &enableSSHCA,
	}, nil
}

func durationPtr(d *duration.Duration) *provisioner.Duration {
	if d == nil {
		return nil
	}
	return &provisioner.Duration{
		Duration: time.Duration(d.Seconds)*time.Second + time.Duration(d.Nanos)*time.Nanosecond,
	}
}

func durationValue(d *duration.Duration) provisioner.Duration {
	if d == nil {
		return provisioner.Duration{}
	}
	return provisioner.Duration{
		Duration: time.Duration(d.Seconds)*time.Second + time.Duration(d.Nanos)*time.Nanosecond,
	}
}

func marshalDetails(d *ProvisionerDetails) (sql.NullString, error) {
	b, err := json.Marshal(d.GetData())
	if err != nil {
		return sql.NullString{}, nil
	}
	return sql.NullString{
		String: string(b),
		Valid:  len(b) > 0,
	}, nil
}

func unmarshalDetails(ctx context.Context, db database.DB, typ ProvisionerType, s sql.NullString) (*ProvisionerDetails, error) {
	if !s.Valid {
		return nil, nil
	}
	var v isProvisionerDetails_Data
	switch typ {
	case ProvisionerType_JWK:
		p := new(ProvisionerDetails_JWK)
		if err := json.Unmarshal([]byte(s.String), p); err != nil {
			return nil, err
		}
		if p.JWK.Key.Key == nil {
			key, err := LoadKey(ctx, db, p.JWK.Key.Id.Id)
			if err != nil {
				return nil, err
			}
			p.JWK.Key = key
		}
		return &ProvisionerDetails{Data: p}, nil
	case ProvisionerType_OIDC:
		v = new(ProvisionerDetails_OIDC)
	case ProvisionerType_GCP:
		v = new(ProvisionerDetails_GCP)
	case ProvisionerType_AWS:
		v = new(ProvisionerDetails_AWS)
	case ProvisionerType_AZURE:
		v = new(ProvisionerDetails_Azure)
	case ProvisionerType_ACME:
		v = new(ProvisionerDetails_ACME)
	case ProvisionerType_X5C:
		p := new(ProvisionerDetails_X5C)
		if err := json.Unmarshal([]byte(s.String), p); err != nil {
			return nil, err
		}
		for _, k := range p.X5C.GetRoots() {
			if err := k.Select(ctx, db, k.Id.Id); err != nil {
				return nil, err
			}
		}
		return &ProvisionerDetails{Data: p}, nil
	case ProvisionerType_K8SSA:
		p := new(ProvisionerDetails_K8SSA)
		if err := json.Unmarshal([]byte(s.String), p); err != nil {
			return nil, err
		}
		for _, k := range p.K8SSA.GetPublicKeys() {
			if err := k.Select(ctx, db, k.Id.Id); err != nil {
				return nil, err
			}
		}
		return &ProvisionerDetails{Data: p}, nil
	case ProvisionerType_SSHPOP:
		v = new(ProvisionerDetails_SSHPOP)
	default:
		return nil, fmt.Errorf("unsupported provisioner type %s", typ)
	}

	if err := json.Unmarshal([]byte(s.String), v); err != nil {
		return nil, err
	}
	return &ProvisionerDetails{Data: v}, nil
}

func marshalClaims(c *Claims) (sql.NullString, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return sql.NullString{}, nil
	}
	return sql.NullString{
		String: string(b),
		Valid:  len(b) > 0,
	}, nil
}

func unmarshalClaims(s sql.NullString) (*Claims, error) {
	if !s.Valid {
		return nil, nil
	}
	v := new(Claims)
	return v, json.Unmarshal([]byte(s.String), v)
}
*/
