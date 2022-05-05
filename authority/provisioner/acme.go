package provisioner

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

// ACME is the acme provisioner type, an entity that can authorize the ACME
// provisioning flow.
type ACME struct {
	*base
	ID      string `json:"-"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	ForceCN bool   `json:"forceCN,omitempty"`
	// RequireEAB makes the provisioner require ACME EAB to be provided
	// by clients when creating a new Account. If set to true, the provided
	// EAB will be verified. If set to false and an EAB is provided, it is
	// not verified. Defaults to false.
	RequireEAB bool     `json:"requireEAB,omitempty"`
	Claims     *Claims  `json:"claims,omitempty"`
	Options    *Options `json:"options,omitempty"`

	ctl *Controller
}

// GetID returns the provisioner unique identifier.
func (p ACME) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *ACME) GetIDForToken() string {
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

// GetOptions returns the configured provisioner options.
func (p *ACME) GetOptions() *Options {
	return p.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by
// the provisioner.
func (p *ACME) DefaultTLSCertDuration() time.Duration {
	return p.ctl.Claimer.DefaultTLSCertDuration()
}

// Init initializes and validates the fields of an ACME type.
func (p *ACME) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// ACMEIdentifierType encodes ACME Identifier types
type ACMEIdentifierType string

const (
	// IP is the ACME ip identifier type
	IP ACMEIdentifierType = "ip"
	// DNS is the ACME dns identifier type
	DNS ACMEIdentifierType = "dns"
)

// ACMEIdentifier encodes ACME Order Identifiers
type ACMEIdentifier struct {
	Type  ACMEIdentifierType
	Value string
}

// AuthorizeOrderIdentifier verifies the provisioner is allowed to issue a
// certificate for an ACME Order Identifier.
func (p *ACME) AuthorizeOrderIdentifier(ctx context.Context, identifier ACMEIdentifier) error {

	x509Policy := p.ctl.getPolicy().getX509()

	// identifier is allowed if no policy is configured
	if x509Policy == nil {
		return nil
	}

	// assuming only valid identifiers (IP or DNS) are provided
	var err error
	switch identifier.Type {
	case IP:
		err = x509Policy.IsIPAllowed(net.ParseIP(identifier.Value))
	case DNS:
		err = x509Policy.IsDNSAllowed(identifier.Value)
	default:
		err = fmt.Errorf("invalid ACME identifier type '%s' provided", identifier.Type)
	}

	return err
}

// AuthorizeSign does not do any validation, because all validation is handled
// in the ACME protocol. This method returns a list of modifiers / constraints
// on the resulting certificate.
func (p *ACME) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	opts := []SignOption{
		p,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeACME, p.Name, ""),
		newForceCNOption(p.ForceCN),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
	}

	return opts, nil
}

// AuthorizeRevoke is called just before the certificate is to be revoked by
// the CA. It can be used to authorize revocation of a certificate. It
// currently is a no-op.
// TODO(hs): add configuration option that toggles revocation? Or change function signature to make it more useful?
// Or move certain logic out of the Revoke API to here? Would likely involve some more stuff in the ctx.
func (p *ACME) AuthorizeRevoke(ctx context.Context, token string) error {
	return nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *ACME) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}
