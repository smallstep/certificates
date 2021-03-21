package provisioner

import (
	"context"
	"time"

	"github.com/pkg/errors"
)

// SCEP is the SCEP provisioner type, an entity that can authorize the
// SCEP provisioning flow
type SCEP struct {
	*base
	Type string `json:"type"`
	Name string `json:"name"`

	ForceCN           bool     `json:"forceCN,omitempty"`
	ChallengePassword string   `json:"challenge,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	Options           *Options `json:"options,omitempty"`
	Claims            *Claims  `json:"claims,omitempty"`
	claimer           *Claimer
}

// GetID returns the provisioner unique identifier.
func (s SCEP) GetID() string {
	return "scep/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *SCEP) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *SCEP) GetType() Type {
	return TypeSCEP
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *SCEP) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token.
func (s *SCEP) GetTokenID(ott string) (string, error) {
	return "", errors.New("scep provisioner does not implement GetTokenID")
}

// GetOptions returns the configured provisioner options.
func (s *SCEP) GetOptions() *Options {
	return s.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by
// the provisioner.
func (s *SCEP) DefaultTLSCertDuration() time.Duration {
	return s.claimer.DefaultTLSCertDuration()
}

// Init initializes and validates the fields of a SCEP type.
func (s *SCEP) Init(config Config) (err error) {

	switch {
	case s.Type == "":
		return errors.New("provisioner type cannot be empty")
	case s.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	// Update claims with global ones
	if s.claimer, err = NewClaimer(s.Claims, config.Claims); err != nil {
		return err
	}

	// TODO: add other, SCEP specific, options?

	return err
}

// AuthorizeSign does not do any verification, because all verification is handled
// in the SCEP protocol. This method returns a list of modifiers / constraints
// on the resulting certificate.
func (s *SCEP) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	return []SignOption{
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeSCEP, s.Name, ""),
		newForceCNOption(s.ForceCN),
		profileDefaultDuration(s.claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(s.claimer.MinTLSCertDuration(), s.claimer.MaxTLSCertDuration()),
	}, nil
}

// GetChallengePassword returns the challenge password
func (s *SCEP) GetChallengePassword() string {
	return s.ChallengePassword
}

// GetCapabilities returns the CA capabilities
func (s *SCEP) GetCapabilities() []string {
	return s.Capabilities
}
