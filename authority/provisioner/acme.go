package provisioner

import (
	"context"
	"crypto/x509"

	"github.com/pkg/errors"
)

// ACME is the acme provisioner type, an entity that can authorize the ACME
// provisioning flow.
type ACME struct {
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Claims  *Claims `json:"claims,omitempty"`
	claimer *Claimer
}

// GetID returns the provisioner unique identifier.
func (p ACME) GetID() string {
	return "acme/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *ACME) GetTokenID(ott string) (string, error) {
	return "", errors.New("acme provisioner does not implement GetTokenID")
}

// GetName returns the name of the provisioner.
func (p *ACME) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *ACME) GetType() Type {
	return TypeACME
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *ACME) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// Init initializes and validates the fields of a JWK type.
func (p *ACME) Init(config Config) (err error) {
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

	return err
}

// AuthorizeRevoke is not implemented yet for the ACME provisioner.
func (p *ACME) AuthorizeRevoke(token string) error {
	return nil
}

// AuthorizeSign validates the given token.
func (p *ACME) AuthorizeSign(ctx context.Context, _ string) ([]SignOption, error) {
	if m := MethodFromContext(ctx); m != SignMethod {
		return nil, errors.Errorf("unexpected method type %d in context", m)
	}
	return []SignOption{
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeACME, p.Name, ""),
		x509ProfileValidityModifier{p.claimer, 0},
		// validators
		defaultPublicKeyValidator{},
		validityValidator{},
		x509CertificateDurationValidator{p.claimer, 0},
	}, nil
}

// AuthorizeRenewal is not implemented for the ACME provisioner.
func (p *ACME) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}
