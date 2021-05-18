package mgmt

import (
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
)

// AuthConfig represents the Authority Configuration.
type AuthConfig struct {
	//*cas.Options         `json:"cas"`
	ID           string         `json:"id"`
	ASN1DN       *config.ASN1DN `json:"asn1dn,omitempty"`
	Provisioners []*Provisioner `json:"-"`
	Admins       []*Admin       `json:"-"`
	Claims       *Claims        `json:"claims,omitempty"`
	Backdate     string         `json:"backdate,omitempty"`
	Status       StatusType     `json:"status,omitempty"`
}

func NewDefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Claims:   NewDefaultClaims(),
		ASN1DN:   &config.ASN1DN{},
		Backdate: config.DefaultBackdate.String(),
		Status:   StatusActive,
	}
}

// ToCertificates converts a mgmt AuthConfig to configuration that can be
// directly used by the `step-ca` process. Resources are normalized and
// initialized.
func (ac *AuthConfig) ToCertificates() (*config.AuthConfig, error) {
	claims, err := ac.Claims.ToCertificates()
	if err != nil {
		return nil, err
	}
	backdate, err := provisioner.NewDuration(ac.Backdate)
	if err != nil {
		return nil, WrapErrorISE(err, "error converting backdate %s to duration", ac.Backdate)
	}
	var provs []provisioner.Interface
	for _, p := range ac.Provisioners {
		authProv, err := p.ToCertificates()
		if err != nil {
			return nil, err
		}
		provs = append(provs, authProv)
	}
	var admins []*admin.Admin
	for _, adm := range ac.Admins {
		authAdmin, err := adm.ToCertificates()
		if err != nil {
			return nil, err
		}
		admins = append(admins, authAdmin)
	}
	return &config.AuthConfig{
		AuthorityID:          ac.ID,
		Provisioners:         provs,
		Admins:               admins,
		Template:             ac.ASN1DN,
		Claims:               claims,
		DisableIssuedAtCheck: false,
		Backdate:             backdate,
	}, nil
}
