package provisioner

import (
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// X5C is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type X5C struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Roots     string `json:"roots"`
	rootPool  *x509.CertPool
	Claims    *Claims `json:"claims,omitempty"`
	claimer   *Claimer
	audiences Audiences
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any X5C provisioner.
func (p *X5C) GetID() string {
	return p.Name
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

	p.audiences = config.Audiences
	return err
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *X5C) authorizeToken(token string, audiences []string) (*jwtPayload, error) {
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

	var claims jwtPayload
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

	if claims.Subject == "" {
		return nil, errors.New("token subject cannot be empty")
	}

	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *X5C) AuthorizeRevoke(token string) error {
	_, err := p.authorizeToken(token, p.audiences.Revoke)
	return err
}

// AuthorizeSign validates the given token.
func (p *X5C) AuthorizeSign(token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token, p.audiences.Sign)
	if err != nil {
		return nil, err
	}
	// NOTE: This is for backwards compatibility with older versions of cli
	// and certificates. Older versions added the token subject as the only SAN
	// in a CSR by default.
	if len(claims.SANs) == 0 {
		claims.SANs = []string{claims.Subject}
	}

	dnsNames, ips, emails := x509util.SplitSANs(claims.SANs)
	return []SignOption{
		defaultPublicKeyValidator{},
		commonNameValidator(claims.Subject),
		dnsNamesValidator(dnsNames),
		ipAddressesValidator(ips),
		emailAddressesValidator(emails),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		newProvisionerExtensionOption(TypeX5C, p.Name, ""),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	}, nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *X5C) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}
