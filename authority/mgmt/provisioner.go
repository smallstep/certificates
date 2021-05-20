package mgmt

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/authority/status"
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

type ProvisionerType string

var (
	ProvisionerTypeACME   = ProvisionerType("ACME")
	ProvisionerTypeAWS    = ProvisionerType("AWS")
	ProvisionerTypeAZURE  = ProvisionerType("AZURE")
	ProvisionerTypeGCP    = ProvisionerType("GCP")
	ProvisionerTypeJWK    = ProvisionerType("JWK")
	ProvisionerTypeK8SSA  = ProvisionerType("K8SSA")
	ProvisionerTypeOIDC   = ProvisionerType("OIDC")
	ProvisionerTypeSSHPOP = ProvisionerType("SSHPOP")
	ProvisionerTypeX5C    = ProvisionerType("X5C")
)

func NewProvisionerCtx(opts ...ProvisionerOption) *ProvisionerCtx {
	pc := &ProvisionerCtx{
		Claims: NewDefaultClaims(),
	}
	for _, o := range opts {
		o(pc)
	}
	return pc
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

type unmarshalProvisioner struct {
	ID               string          `json:"-"`
	AuthorityID      string          `json:"-"`
	Type             string          `json:"type"`
	Name             string          `json:"name"`
	Claims           *Claims         `json:"claims"`
	Details          json.RawMessage `json:"details"`
	X509Template     string          `json:"x509Template"`
	X509TemplateData []byte          `json:"x509TemplateData"`
	SSHTemplate      string          `json:"sshTemplate"`
	SSHTemplateData  []byte          `json:"sshTemplateData"`
	Status           status.Type     `json:"status"`
}

// Provisioner type.
type Provisioner struct {
	ID               string             `json:"-"`
	AuthorityID      string             `json:"-"`
	Type             string             `json:"type"`
	Name             string             `json:"name"`
	Claims           *Claims            `json:"claims"`
	Details          ProvisionerDetails `json:"details"`
	X509Template     string             `json:"x509Template"`
	X509TemplateData []byte             `json:"x509TemplateData"`
	SSHTemplate      string             `json:"sshTemplate"`
	SSHTemplateData  []byte             `json:"sshTemplateData"`
	Status           status.Type        `json:"status"`
}

type typ struct {
	Type ProvisionerType `json:"type"`
}

// UnmarshalJSON implements the Unmarshal interface.
func (p *Provisioner) UnmarshalJSON(b []byte) error {
	var (
		err error
		up  = new(unmarshalProvisioner)
	)
	if err = json.Unmarshal(b, up); err != nil {
		return WrapErrorISE(err, "error unmarshaling provisioner to intermediate type")
	}
	p.Details, err = UnmarshalProvisionerDetails(up.Details)
	if err = json.Unmarshal(b, up); err != nil {
		return WrapErrorISE(err, "error unmarshaling provisioner details")
	}

	p.ID = up.ID
	p.AuthorityID = up.AuthorityID
	p.Type = up.Type
	p.Name = up.Name
	p.Claims = up.Claims
	p.X509Template = up.X509Template
	p.X509TemplateData = up.X509TemplateData
	p.SSHTemplate = up.SSHTemplate
	p.SSHTemplateData = up.SSHTemplateData
	p.Status = up.Status

	return nil
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
	pc := NewProvisionerCtx(opts...)
	details, err := NewProvisionerDetails(ProvisionerType(typ), pc)
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
		Status:           status.Active,
	}

	if err := db.CreateProvisioner(ctx, p); err != nil {
		return nil, WrapErrorISE(err, "error creating provisioner")
	}
	return p, nil
}

// ProvisionerDetails is the interface implemented by all provisioner details
// attributes.
type ProvisionerDetails interface {
	isProvisionerDetails()
}

// ProvisionerDetailsJWK represents the values required by a JWK provisioner.
type ProvisionerDetailsJWK struct {
	Type       ProvisionerType `json:"type"`
	PublicKey  []byte          `json:"publicKey"`
	PrivateKey string          `json:"PrivateKey"`
}

// ProvisionerDetailsOIDC represents the values required by a OIDC provisioner.
type ProvisionerDetailsOIDC struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsGCP represents the values required by a GCP provisioner.
type ProvisionerDetailsGCP struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsAWS represents the values required by a AWS provisioner.
type ProvisionerDetailsAWS struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsAzure represents the values required by a Azure provisioner.
type ProvisionerDetailsAzure struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsACME represents the values required by a ACME provisioner.
type ProvisionerDetailsACME struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsX5C represents the values required by a X5C provisioner.
type ProvisionerDetailsX5C struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsK8SSA represents the values required by a K8SSA provisioner.
type ProvisionerDetailsK8SSA struct {
	Type ProvisionerType `json:"type"`
}

// ProvisionerDetailsSSHPOP represents the values required by a SSHPOP provisioner.
type ProvisionerDetailsSSHPOP struct {
	Type ProvisionerType `json:"type"`
}

func (*ProvisionerDetailsJWK) isProvisionerDetails() {}

func (*ProvisionerDetailsOIDC) isProvisionerDetails() {}

func (*ProvisionerDetailsGCP) isProvisionerDetails() {}

func (*ProvisionerDetailsAWS) isProvisionerDetails() {}

func (*ProvisionerDetailsAzure) isProvisionerDetails() {}

func (*ProvisionerDetailsACME) isProvisionerDetails() {}

func (*ProvisionerDetailsX5C) isProvisionerDetails() {}

func (*ProvisionerDetailsK8SSA) isProvisionerDetails() {}

func (*ProvisionerDetailsSSHPOP) isProvisionerDetails() {}

func NewProvisionerDetails(typ ProvisionerType, pc *ProvisionerCtx) (ProvisionerDetails, error) {
	switch typ {
	case ProvisionerTypeJWK:
		return createJWKDetails(pc)
		/*
			case ProvisionerTypeOIDC:
				return createOIDCDetails(pc)
			case ProvisionerTypeACME:
				return createACMEDetails(pc)
			case ProvisionerTypeK8SSA:
				return createK8SSADetails(pc)
			case ProvisionerTypeSSHPOP:
				return createSSHPOPDetails(pc)
			case ProvisionerTypeX5C:
				return createSSHPOPDetails(pc)
		*/
	default:
		return nil, NewErrorISE("unsupported provisioner type %s", typ)
	}
}

func createJWKDetails(pc *ProvisionerCtx) (*ProvisionerDetailsJWK, error) {
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

	return &ProvisionerDetailsJWK{
		Type:       ProvisionerTypeJWK,
		PublicKey:  jwkPubBytes,
		PrivateKey: jwePrivStr,
	}, nil
}

// ToCertificates converts the landlord provisioner type to the open source
// provisioner type.
func (p *Provisioner) ToCertificates() (provisioner.Interface, error) {
	claims, err := p.Claims.ToCertificates()
	if err != nil {
		return nil, err
	}

	switch details := p.Details.(type) {
	case *ProvisionerDetailsJWK:
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(details.PublicKey, &jwk); err != nil {
			return nil, err
		}
		return &provisioner.JWK{
			ID:           p.ID,
			Type:         p.Type,
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: details.PrivateKey,
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

type detailsType struct {
	Type ProvisionerType
}

func UnmarshalProvisionerDetails(data json.RawMessage) (ProvisionerDetails, error) {
	dt := new(detailsType)
	if err := json.Unmarshal(data, dt); err != nil {
		return nil, WrapErrorISE(err, "error unmarshaling provisioner details")
	}

	var v ProvisionerDetails
	switch dt.Type {
	case ProvisionerTypeJWK:
		v = new(ProvisionerDetailsJWK)
	case ProvisionerTypeOIDC:
		v = new(ProvisionerDetailsOIDC)
	case ProvisionerTypeGCP:
		v = new(ProvisionerDetailsGCP)
	case ProvisionerTypeAWS:
		v = new(ProvisionerDetailsAWS)
	case ProvisionerTypeAZURE:
		v = new(ProvisionerDetailsAzure)
	case ProvisionerTypeACME:
		v = new(ProvisionerDetailsACME)
	case ProvisionerTypeX5C:
		v = new(ProvisionerDetailsX5C)
	case ProvisionerTypeK8SSA:
		v = new(ProvisionerDetailsK8SSA)
	case ProvisionerTypeSSHPOP:
		v = new(ProvisionerDetailsSSHPOP)
	default:
		return nil, fmt.Errorf("unsupported provisioner type %s", dt.Type)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return v, nil
}
