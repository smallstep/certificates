package mgmt

import (
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/linkedca"
	"go.step.sm/crypto/jose"
)

/*
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

type typ struct {
	Type linkedca.Provisioner_Type `json:"type"`
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
*/

func provisionerGetOptions(p *linkedca.Provisioner) *provisioner.Options {
	return &provisioner.Options{
		X509: &provisioner.X509Options{
			Template:     string(p.X509Template),
			TemplateData: p.X509TemplateData,
		},
		SSH: &provisioner.SSHOptions{
			Template:     string(p.SshTemplate),
			TemplateData: p.SshTemplateData,
		},
	}
}

// provisionerToCertificates converts the landlord provisioner type to the open source
// provisioner type.
func provisionerToCertificates(p *linkedca.Provisioner) (provisioner.Interface, error) {
	claims, err := claimsToCertificates(p.Claims)
	if err != nil {
		return nil, err
	}

	details := p.Details.GetData()
	if details == nil {
		return nil, fmt.Errorf("provisioner does not have any details")
	}

	switch d := details.(type) {
	case *linkedca.ProvisionerDetails_JWK:
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(d.JWK.PublicKey, &jwk); err != nil {
			return nil, err
		}
		return &provisioner.JWK{
			ID:           p.Id,
			Type:         p.Type.String(),
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: string(d.JWK.EncryptedPrivateKey),
			Claims:       claims,
			Options:      provisionerGetOptions(p),
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

// claimsToCertificates converts the landlord provisioner claims type to the open source
// (step-ca) claims type.
func claimsToCertificates(c *linkedca.Claims) (*provisioner.Claims, error) {
	var durs = map[string]struct {
		durStr string
		dur    *provisioner.Duration
	}{
		"minTLSDur":         {durStr: c.X509.Durations.Min},
		"maxTLSDur":         {durStr: c.X509.Durations.Max},
		"defaultTLSDur":     {durStr: c.X509.Durations.Default},
		"minSSHUserDur":     {durStr: c.Ssh.UserDurations.Min},
		"maxSSHUserDur":     {durStr: c.Ssh.UserDurations.Max},
		"defaultSSHUserDur": {durStr: c.Ssh.UserDurations.Default},
		"minSSHHostDur":     {durStr: c.Ssh.HostDurations.Min},
		"maxSSHHostDur":     {durStr: c.Ssh.HostDurations.Max},
		"defaultSSHHostDur": {durStr: c.Ssh.HostDurations.Default},
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
		EnableSSHCA:       &c.Ssh.Enabled,
	}, nil
}

/*
type detailsType struct {
	Type ProvisionerType
}

// UnmarshalProvisionerDetails unmarshals bytes into the proper details type.
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
*/
