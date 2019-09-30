package provisioner

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// x5cPayload extends jwt.Claims with step attributes.
type x5cPayload struct {
	jose.Claims
	SANs   []string     `json:"sans,omitempty"`
	Step   *stepPayload `json:"step,omitempty"`
	chains [][]*x509.Certificate
}

// X5C is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type X5C struct {
	Type      string  `json:"type"`
	Name      string  `json:"name"`
	Roots     string  `json:"roots"`
	Claims    *Claims `json:"claims,omitempty"`
	claimer   *Claimer
	audiences Audiences
	rootPool  *x509.CertPool
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any X5C provisioner.
func (p *X5C) GetID() string {
	return "x5c/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *X5C) GetTokenID(ott string) (string, error) {
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
func (p *X5C) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *X5C) GetType() Type {
	return TypeX5C
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *X5C) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// Init initializes and validates the fields of a X5C type.
func (p *X5C) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.Roots == "":
		return errors.New("provisioner root(s) cannot be empty")
	}

	p.rootPool = x509.NewCertPool()
	if len(p.Roots) > 0 && !p.rootPool.AppendCertsFromPEM([]byte(p.Roots)) {
		return errors.Errorf("error parsing root certificate(s) for provisioner '%s'", p.Name)
	}

	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}

	p.audiences = config.Audiences.WithFragment(p.GetID())
	return err
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *X5C) authorizeToken(token string, audiences []string) (*x5cPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	verifiedChains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
		Roots: p.rootPool,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error verifying x5c certificate chain")
	}
	leaf := verifiedChains[0][0]

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("certificate used to sign x5c token cannot be used for digital signature")
	}

	// Using the leaf certificates key to validate the claims accomplishes two
	// things:
	//   1. Asserts that the private key used to sign the token corresponds
	//      to the public certificate in the `x5c` header of the token.
	//   2. Asserts that the claims are valid - have not been tampered with.
	var claims x5cPayload
	if err = jwt.Claims(leaf.PublicKey, &claims); err != nil {
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

	// Save the verified chains on the x5c payload object.
	claims.chains = verifiedChains
	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *X5C) AuthorizeRevoke(token string) error {
	_, err := p.authorizeToken(token, p.audiences.Revoke)
	return err
}

// AuthorizeSign validates the given token.
func (p *X5C) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token, p.audiences.Sign)
	if err != nil {
		return nil, err
	}

	// Check for SSH sign-ing request.
	if MethodFromContext(ctx) == SignSSHMethod {
		if !p.claimer.IsSSHCAEnabled() {
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

	// Get the remaining duration from the provisioning cert. The duration
	// on the new certificate cannot be greater than the remaining duration of
	// the provisioning certificate.
	rem := claims.chains[0][0].NotAfter.Sub(now())

	return []SignOption{
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeX5C, p.Name, ""),
		profileProvCredDuration{p.claimer.DefaultTLSCertDuration(), rem},
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
func (p *X5C) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// authorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *X5C) authorizeSSHSign(claims *x5cPayload) ([]SignOption, error) {
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

	rem := claims.chains[0][0].NotAfter.Sub(now())

	return append(signOptions,
		// Set the default extensions.
		&sshDefaultExtensionModifier{},
		// Checks the validity bounds, and set the validity if has not been set.
		&sshProvisioningCredTemporalModifier{p.claimer, rem},
		// Validate public key.
		&sshDefaultPublicKeyValidator{},
		// Require all the fields in the SSH certificate
		&sshCertificateDefaultValidator{p.claimer},
	), nil
}
