package provisioner

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
)

// jwtPayload extends jwt.Claims with step attributes.
type jwtPayload struct {
	jose.Claims
	SANs []string     `json:"sans,omitempty"`
	Step *stepPayload `json:"step,omitempty"`
}

type stepPayload struct {
	SSH *SignSSHOptions `json:"ssh,omitempty"`
}

// JWK is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type JWK struct {
	*base
	ID           string           `json:"-"`
	Type         string           `json:"type"`
	Name         string           `json:"name"`
	Key          *jose.JSONWebKey `json:"key"`
	EncryptedKey string           `json:"encryptedKey,omitempty"`
	Claims       *Claims          `json:"claims,omitempty"`
	Options      *Options         `json:"options,omitempty"`
	claimer      *Claimer
	audiences    Audiences
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any JWK provisioner.
func (p *JWK) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *JWK) GetIDForToken() string {
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
		return nil, errs.Wrap(http.StatusUnauthorized, err, "jwk.authorizeToken; error parsing jwk token")
	}

	var claims jwtPayload
	if err = jwt.Claims(p.Key, &claims); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "jwk.authorizeToken; error parsing jwk claims")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: p.Name,
		Time:   time.Now().UTC(),
	}, time.Minute); err != nil {
		return nil, errs.Wrapf(http.StatusUnauthorized, err, "jwk.authorizeToken; invalid jwk claims")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, audiences) {
		return nil, errs.Unauthorized("jwk.authorizeToken; invalid jwk token audience claim (aud); want %s, but got %s",
			audiences, claims.Audience)
	}

	if claims.Subject == "" {
		return nil, errs.Unauthorized("jwk.authorizeToken; jwk token subject cannot be empty")
	}

	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *JWK) AuthorizeRevoke(ctx context.Context, token string) error {
	_, err := p.authorizeToken(token, p.audiences.Revoke)
	return errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeRevoke")
}

// AuthorizeSign validates the given token.
func (p *JWK) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token, p.audiences.Sign)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSign")
	}

	// NOTE: This is for backwards compatibility with older versions of cli
	// and certificates. Older versions added the token subject as the only SAN
	// in a CSR by default.
	if len(claims.SANs) == 0 {
		claims.SANs = []string{claims.Subject}
	}

	// Certificate templates
	data := x509util.CreateTemplateData(claims.Subject, claims.SANs)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := TemplateOptions(p.Options, data)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSign")
	}

	return []SignOption{
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeJWK, p.Name, p.Key.KeyID),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		// validators
		commonNameValidator(claims.Subject),
		defaultPublicKeyValidator{},
		defaultSANsValidator(claims.SANs),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	}, nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *JWK) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errs.Unauthorized("jwk.AuthorizeRenew; renew is disabled for jwk provisioner '%s'", p.GetName())
	}
	return nil
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *JWK) AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error) {
	if !p.claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("jwk.AuthorizeSSHSign; sshCA is disabled for jwk provisioner '%s'", p.GetName())
	}
	claims, err := p.authorizeToken(token, p.audiences.SSHSign)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSSHSign")
	}
	if claims.Step == nil || claims.Step.SSH == nil {
		return nil, errs.Unauthorized("jwk.AuthorizeSSHSign; jwk token must be an SSH provisioning token")
	}

	opts := claims.Step.SSH
	signOptions := []SignOption{
		// validates user's SignSSHOptions with the ones in the token
		sshCertOptionsValidator(*opts),
		// validate users's KeyID is the token subject.
		sshCertOptionsValidator(SignSSHOptions{KeyID: claims.Subject}),
	}

	// Default template attributes.
	certType := sshutil.UserCert
	keyID := claims.Subject
	principals := []string{claims.Subject}

	// Use options in the token.
	if opts.CertType != "" {
		if certType, err = sshutil.CertTypeFromString(opts.CertType); err != nil {
			return nil, errs.Wrap(http.StatusBadRequest, err, "jwk.AuthorizeSSHSign")
		}
	}
	if opts.KeyID != "" {
		keyID = opts.KeyID
	}
	if len(opts.Principals) > 0 {
		principals = opts.Principals
	}

	// Certificate templates.
	data := sshutil.CreateTemplateData(certType, keyID, principals)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := TemplateSSHOptions(p.Options, data)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSign")
	}
	signOptions = append(signOptions, templateOptions)

	// Add modifiers from custom claims
	t := now()
	if !opts.ValidAfter.IsZero() {
		signOptions = append(signOptions, sshCertValidAfterModifier(opts.ValidAfter.RelativeTime(t).Unix()))
	}
	if !opts.ValidBefore.IsZero() {
		signOptions = append(signOptions, sshCertValidBeforeModifier(opts.ValidBefore.RelativeTime(t).Unix()))
	}

	return append(signOptions,
		// Set the validity bounds if not set.
		&sshDefaultDuration{p.claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.claimer},
		// Require and validate all the default fields in the SSH certificate.
		&sshCertDefaultValidator{},
	), nil
}

// AuthorizeSSHRevoke returns nil if the token is valid, false otherwise.
func (p *JWK) AuthorizeSSHRevoke(ctx context.Context, token string) error {
	_, err := p.authorizeToken(token, p.audiences.SSHRevoke)
	return errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSSHRevoke")
}
