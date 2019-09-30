package provisioner

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// jwtPayload extends jwt.Claims with step attributes.
type jwtPayload struct {
	jose.Claims
	SANs []string     `json:"sans,omitempty"`
	Step *stepPayload `json:"step,omitempty"`
}

type stepPayload struct {
	SSH *SSHOptions `json:"ssh,omitempty"`
}

// JWK is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type JWK struct {
	Type         string           `json:"type"`
	Name         string           `json:"name"`
	Key          *jose.JSONWebKey `json:"key"`
	EncryptedKey string           `json:"encryptedKey,omitempty"`
	Claims       *Claims          `json:"claims,omitempty"`
	claimer      *Claimer
	audiences    Audiences
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any JWK provisioner.
func (p *JWK) GetID() string {
	return p.Name + ":" + p.Key.KeyID
}

// GetTokenID returns the identifier of the token.
func (p *JWK) GetTokenID(ott string) (string, error) {
	// Validate payload
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims jose.Claims
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}
	return claims.ID, nil
}

// GetName returns the name of the provisioner.
func (p *JWK) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *JWK) GetType() Type {
	return TypeJWK
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *JWK) GetEncryptedKey() (string, string, bool) {
	return p.Key.KeyID, p.EncryptedKey, len(p.EncryptedKey) > 0
}

// Init initializes and validates the fields of a JWK type.
func (p *JWK) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.Key == nil:
		return errors.New("provisioner key cannot be empty")
	}

	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}

	p.audiences = config.Audiences
	return err
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *JWK) authorizeToken(token string, audiences []string) (*jwtPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	var claims jwtPayload
	if err = jwt.Claims(p.Key, &claims); err != nil {
		return nil, errors.Wrap(err, "error parsing claims")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: p.Name,
		Time:   time.Now().UTC(),
	}, time.Minute); err != nil {
		return nil, errors.Wrapf(err, "invalid token")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, audiences) {
		return nil, errors.New("invalid token: invalid audience claim (aud)")
	}

	if claims.Subject == "" {
		return nil, errors.New("token subject cannot be empty")
	}

	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *JWK) AuthorizeRevoke(token string) error {
	_, err := p.authorizeToken(token, p.audiences.Revoke)
	return err
}

// AuthorizeSign validates the given token.
func (p *JWK) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token, p.audiences.Sign)
	if err != nil {
		return nil, err
	}

	// Check for SSH sign-ing request.
	if MethodFromContext(ctx) == SignSSHMethod {
		if p.claimer.IsSSHCAEnabled() == false {
			return nil, errors.Errorf("ssh ca is disabled for provisioner %s", p.GetID())
		}
		return p.authorizeSSHSign(claims)
	}

	// NOTE: This is for backwards compatibility with older versions of cli
	// and certificates. Older versions added the token subject as the only SAN
	// in a CSR by default.
	if len(claims.SANs) == 0 {
		claims.SANs = []string{claims.Subject}
	}

	dnsNames, ips, emails := x509util.SplitSANs(claims.SANs)
	return []SignOption{
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeJWK, p.Name, p.Key.KeyID),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		// validators
		commonNameValidator(claims.Subject),
		defaultPublicKeyValidator{},
		dnsNamesValidator(dnsNames),
		emailAddressesValidator(emails),
		ipAddressesValidator(ips),
		newTemporalValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	}, nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *JWK) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// authorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *JWK) authorizeSSHSign(claims *jwtPayload) ([]SignOption, error) {
	t := now()
	if claims.Step == nil || claims.Step.SSH == nil {
		return nil, errors.New("authorization token must be an SSH provisioning token")
	}
	opts := claims.Step.SSH
	signOptions := []SignOption{
		// validates user's SSHOptions with the ones in the token
		sshCertificateOptionsValidator(*opts),
		// set the key id to the token subject
		sshCertificateKeyIDModifier(claims.Subject),
	}

	// Add modifiers from custom claims
	if opts.CertType != "" {
		signOptions = append(signOptions, sshCertificateCertTypeModifier(opts.CertType))
	}
	if len(opts.Principals) > 0 {
		signOptions = append(signOptions, sshCertificatePrincipalsModifier(opts.Principals))
	}
	if !opts.ValidAfter.IsZero() {
		signOptions = append(signOptions, sshCertificateValidAfterModifier(opts.ValidAfter.RelativeTime(t).Unix()))
	}
	if !opts.ValidBefore.IsZero() {
		signOptions = append(signOptions, sshCertificateValidBeforeModifier(opts.ValidBefore.RelativeTime(t).Unix()))
	}

	// Default to a user certificate with no principals if not set
	signOptions = append(signOptions, sshCertificateDefaultsModifier{CertType: SSHUserCert})

	return append(signOptions,
		// Set the default extensions.
		&sshDefaultExtensionModifier{},
		// Set the validity bounds if not set.
		&sshValidityModifier{p.claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertificateValidityValidator{p.claimer},
		// Require and validate all the default fields in the SSH certificate.
		&sshCertificateDefaultValidator{},
	), nil
}
