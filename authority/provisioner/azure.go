package provisioner

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// azureAttestedDocumentURL is the URL for the attested document.
const azureAttestedDocumentURL = "http://169.254.169.254/metadata/attested/document?api-version=2018-10-01"

type azureConfig struct {
	attestedDocumentURL string
}

func newAzureConfig() *azureConfig {
	return &azureConfig{
		attestedDocumentURL: azureAttestedDocumentURL,
	}
}

// Azure is the provisioner that supports identity tokens created from the
// Microsoft Azure Instance Metadata service.
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
type Azure struct {
	Type                   string  `json:"type"`
	Name                   string  `json:"name"`
	DisableCustomSANs      bool    `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool    `json:"disableTrustOnFirstUse"`
	Claims                 *Claims `json:"claims,omitempty"`
	claimer                *Claimer
	config                 *azureConfig
}

// GetID returns the provisioner unique identifier.
func (p *Azure) GetID() string {
	return "azure:" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *Azure) GetTokenID(token string) (string, error) {
	return "", errors.New("TODO")
}

// GetName returns the name of the provisioner.
func (p *Azure) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *Azure) GetType() Type {
	return TypeAzure
}

// GetEncryptedKey is not available in an Azure provisioner.
func (p *Azure) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

// Init validates and initializes the Azure provisioner.
func (p *Azure) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	}
	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}
	// Initialize configuration
	p.config = newAzureConfig()
	return nil
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *Azure) AuthorizeSign(token string) ([]SignOption, error) {
	return nil, errors.New("TODO")
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *Azure) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error because revoke is not supported on Azure
// provisioners.
func (p *Azure) AuthorizeRevoke(token string) error {
	return errors.New("revoke is not supported on a Azure provisioner")
}
