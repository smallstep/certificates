package mgmt

import (
	"context"

	"github.com/smallstep/certificates/authority/config"
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

func NewDefaultClaims() *linkedca.Claims {
	return &linkedca.Claims{
		X509: &linkedca.X509Claims{
			Durations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinTLSDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxTLSDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultTLSDur.String(),
			},
		},
		Ssh: &linkedca.SSHClaims{
			UserDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinUserSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxUserSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultUserSSHDur.String(),
			},
			HostDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinHostSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxHostSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultHostSSHDur.String(),
			},
		},
		DisableRenewal: config.DefaultDisableRenewal,
	}
}

func CreateFirstProvisioner(ctx context.Context, db DB, password string) (*linkedca.Provisioner, error) {
	jwk, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		return nil, WrapErrorISE(err, "error generating JWK key pair")
	}

	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling JWK")
	}
	jwePrivStr, err := jwe.CompactSerialize()
	if err != nil {
		return nil, WrapErrorISE(err, "error serializing JWE")
	}

	return &linkedca.Provisioner{
		Name:   "Admin JWK",
		Type:   linkedca.Provisioner_JWK,
		Claims: NewDefaultClaims(),
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: &linkedca.JWKProvisioner{
					PublicKey:           jwkPubBytes,
					EncryptedPrivateKey: []byte(jwePrivStr),
				},
			},
		},
	}, nil
}
