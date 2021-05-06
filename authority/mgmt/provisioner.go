package mgmt

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
)

type ProvisionerOption func(*ProvisionerCtx)

type ProvisionerCtx struct {
	JWK                               *jose.JSONWebKey
	JWE                               *jose.JSONWebEncryption
	X509Template, SSHTemplate         string
	X509TemplateData, SSHTemplateData []byte
	Claims                            *Claims
	Password                          string
}

func WithJWK(jwk *jose.JSONWebKey, jwe *jose.JSONWebEncryption) func(*ProvisionerCtx) {
	return func(ctx *ProvisionerCtx) {
		ctx.JWK = jwk
		ctx.JWE = jwe
	}
}

func WithPassword(pass string) func(*ProvisionerCtx) {
	return func(ctx *ProvisionerCtx) {
		ctx.Password = pass
	}
}

// Provisioner type.
type Provisioner struct {
	ID               string      `json:"-"`
	AuthorityID      string      `json:"-"`
	Type             string      `json:"type"`
	Name             string      `json:"name"`
	Claims           *Claims     `json:"claims"`
	Details          interface{} `json:"details"`
	X509Template     string      `json:"x509Template"`
	X509TemplateData []byte      `json:"x509TemplateData"`
	SSHTemplate      string      `json:"sshTemplate"`
	SSHTemplateData  []byte      `json:"sshTemplateData"`
	Status           StatusType  `json:"status"`
}

func (p *Provisioner) GetOptions() *provisioner.Options {
	return &provisioner.Options{
		X509: &provisioner.X509Options{
			Template:     p.X509Template,
			TemplateData: p.X509TemplateData,
		},
		SSH: &provisioner.SSHOptions{
			Template:     p.SSHTemplate,
			TemplateData: p.SSHTemplateData,
		},
	}
}

func CreateProvisioner(ctx context.Context, db DB, typ, name string, opts ...ProvisionerOption) (*Provisioner, error) {
	pc := new(ProvisionerCtx)
	for _, o := range opts {
		o(pc)
	}

	details, err := createJWKDetails(pc)
	if err != nil {
		return nil, err
	}

	p := &Provisioner{
		Type:             typ,
		Name:             name,
		Claims:           pc.Claims,
		Details:          details,
		X509Template:     pc.X509Template,
		X509TemplateData: pc.X509TemplateData,
		SSHTemplate:      pc.SSHTemplate,
		SSHTemplateData:  pc.SSHTemplateData,
		Status:           StatusActive,
	}

	if err := db.CreateProvisioner(ctx, p); err != nil {
		return nil, WrapErrorISE(err, "error creating provisioner")
	}
	return p, nil
}

type ProvisionerDetails_JWK struct {
	PubKey  []byte `json:"pubKey"`
	PrivKey string `json:"privKey"`
}

func createJWKDetails(pc *ProvisionerCtx) (*ProvisionerDetails_JWK, error) {
	var err error

	if pc.JWK != nil && pc.JWE == nil {
		return nil, NewErrorISE("JWE is required with JWK for createJWKProvisioner")
	}
	if pc.JWE != nil && pc.JWK == nil {
		return nil, NewErrorISE("JWK is required with JWE for createJWKProvisioner")
	}
	if pc.JWK == nil && pc.JWE == nil {
		// Create a new JWK w/ encrypted private key.
		if pc.Password == "" {
			return nil, NewErrorISE("password is required to provisioner with new keys")
		}
		pc.JWK, pc.JWE, err = jose.GenerateDefaultKeyPair([]byte(pc.Password))
		if err != nil {
			return nil, WrapErrorISE(err, "error generating JWK key pair")
		}
	}

	jwkPubBytes, err := pc.JWK.MarshalJSON()
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling JWK")
	}
	jwePrivStr, err := pc.JWE.CompactSerialize()
	if err != nil {
		return nil, WrapErrorISE(err, "error serializing JWE")
	}

	return &ProvisionerDetails_JWK{
		PubKey:  jwkPubBytes,
		PrivKey: jwePrivStr,
	}, nil
}

// ToCertificates converts the landlord provisioner type to the open source
// provisioner type.
func (p *Provisioner) ToCertificates() (provisioner.Interface, error) {
	claims, err := p.Claims.ToCertificates()
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	switch details := p.Details.(type) {
	case *ProvisionerDetails_JWK:
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(details.PubKey, &jwk); err != nil {
			return nil, err
		}
		return &provisioner.JWK{
			Type:         p.Type,
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: details.PrivKey,
			Claims:       claims,
			Options:      p.GetOptions(),
		}, nil
		/*
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
		*/
	default:
		return nil, fmt.Errorf("provisioner %s not implemented", p.Type)
	}
}

// ToCertificates converts the landlord provisioner claims type to the open source
// (step-ca) claims type.
func (c *Claims) ToCertificates() (*provisioner.Claims, error) {
	var durs = map[string]struct {
		durStr string
		dur    *provisioner.Duration
	}{
		"minTLSDur":         {durStr: c.X509.Durations.Min},
		"maxTLSDur":         {durStr: c.X509.Durations.Max},
		"defaultTLSDur":     {durStr: c.X509.Durations.Default},
		"minSSHUserDur":     {durStr: c.SSH.UserDurations.Min},
		"maxSSHUserDur":     {durStr: c.SSH.UserDurations.Max},
		"defaultSSHUserDur": {durStr: c.SSH.UserDurations.Default},
		"minSSHHostDur":     {durStr: c.SSH.HostDurations.Min},
		"maxSSHHostDur":     {durStr: c.SSH.HostDurations.Max},
		"defaultSSHHostDur": {durStr: c.SSH.HostDurations.Default},
	}
	var err error
	for k, v := range durs {
		v.dur, err = provisioner.NewDuration(v.durStr)
		if err != nil {
			return nil, WrapErrorISE(err, "error parsing %s %s from claims", k, v.durStr)
		}
	}
	return &provisioner.Claims{
		MinTLSDur:         durs["minTLSDur"].dur,
		MaxTLSDur:         durs["maxTLSDur"].dur,
		DefaultTLSDur:     durs["defaultTLSDur"].dur,
		DisableRenewal:    &c.DisableRenewal,
		MinUserSSHDur:     durs["minSSHUserDur"].dur,
		MaxUserSSHDur:     durs["maxSSHUserDur"].dur,
		DefaultUserSSHDur: durs["defaultSSHUserDur"].dur,
		MinHostSSHDur:     durs["minSSHHostDur"].dur,
		MaxHostSSHDur:     durs["maxSSHHostDur"].dur,
		DefaultHostSSHDur: durs["defaultSSHHostDur"].dur,
		EnableSSHCA:       &c.SSH.Enabled,
	}, nil
}

/*
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
