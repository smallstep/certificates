package provisioner

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"net"
	"time"

	"github.com/pkg/errors"
	nebula "github.com/slackhq/nebula/cert"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x25519"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/errs"
)

const (
	// NebulaCertHeader is the token header that contains a Nebula certificate.
	NebulaCertHeader jose.HeaderKey = "nebula"
)

// Nebula is a provisioner that verifies tokens signed using Nebula private
// keys. The tokens contain a Nebula certificate in the header, which can be
// used to verify the token signature. The certificates are themselves verified
// using the Nebula CA certificates encoded in Roots. The verification process
// is similar to the process for X5C tokens.
//
// Because Nebula "leaf" certificates use X25519 keys, the tokens are signed
// using XEd25519 defined at
// https://signal.org/docs/specifications/xeddsa/#xeddsa and implemented by
// go.step.sm/crypto/x25519.
type Nebula struct {
	ID      string   `json:"-"`
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Roots   []byte   `json:"roots"`
	Claims  *Claims  `json:"claims,omitempty"`
	Options *Options `json:"options,omitempty"`
	caPool  *nebula.NebulaCAPool
	ctl     *Controller
}

// Init verifies and initializes the Nebula provisioner.
func (p *Nebula) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case len(p.Roots) == 0:
		return errors.New("provisioner root(s) cannot be empty")
	}

	p.caPool, err = nebula.NewCAPoolFromBytes(p.Roots)
	if err != nil {
		return errs.InternalServer("failed to create ca pool: %v", err)
	}

	config.Audiences = config.Audiences.WithFragment(p.GetIDForToken())
	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// GetID returns the provisioner id.
func (p *Nebula) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *Nebula) GetIDForToken() string {
	return "nebula/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *Nebula) GetTokenID(token string) (string, error) {
	// Validate payload
	t, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims jose.Claims
	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}
	return claims.ID, nil
}

// GetName returns the name of the provisioner.
func (p *Nebula) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *Nebula) GetType() Type {
	return TypeNebula
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *Nebula) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

// AuthorizeSign returns the list of SignOption for a Sign request.
func (p *Nebula) AuthorizeSign(_ context.Context, token string) ([]SignOption, error) {
	crt, claims, err := p.authorizeToken(token, p.ctl.Audiences.Sign)
	if err != nil {
		return nil, err
	}

	sans := claims.SANs
	if len(sans) == 0 {
		sans = make([]string, len(crt.Details.Ips)+1)
		sans[0] = crt.Details.Name
		for i, ipnet := range crt.Details.Ips {
			sans[i+1] = ipnet.IP.String()
		}
	}

	data := x509util.CreateTemplateData(claims.Subject, sans)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// The Nebula certificate will be available using the template variable
	// AuthorizationCrt. For example {{ .AuthorizationCrt.Details.Groups }} can
	// be used to get all the groups.
	data.SetAuthorizationCertificate(crt)

	templateOptions, err := TemplateOptions(p.Options, data)
	if err != nil {
		return nil, err
	}

	return []SignOption{
		p,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeNebula, p.Name, "").WithControllerOptions(p.ctl),
		profileLimitDuration{
			def:       p.ctl.Claimer.DefaultTLSCertDuration(),
			notBefore: crt.Details.NotBefore,
			notAfter:  crt.Details.NotAfter,
		},
		// validators
		commonNameValidator(claims.Subject),
		nebulaSANsValidator{
			Name: crt.Details.Name,
			IPs:  crt.Details.Ips,
		},
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(data, linkedca.Webhook_X509),
	}, nil
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
// Currently the Nebula provisioner only grants host SSH certificates.
func (p *Nebula) AuthorizeSSHSign(_ context.Context, token string) ([]SignOption, error) {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("ssh is disabled for nebula provisioner '%s'", p.Name)
	}

	crt, claims, err := p.authorizeToken(token, p.ctl.Audiences.SSHSign)
	if err != nil {
		return nil, err
	}

	// Default template attributes.
	keyID := claims.Subject
	principals := make([]string, len(crt.Details.Ips)+1)
	principals[0] = crt.Details.Name
	for i, ipnet := range crt.Details.Ips {
		principals[i+1] = ipnet.IP.String()
	}

	var signOptions []SignOption
	// If step ssh options are given, validate them and set key id, principals
	// and validity.
	if claims.Step != nil && claims.Step.SSH != nil {
		opts := claims.Step.SSH

		// Check that the token only contains valid principals.
		v := nebulaPrincipalsValidator{
			Name: crt.Details.Name,
			IPs:  crt.Details.Ips,
		}
		if err := v.Valid(*opts); err != nil {
			return nil, err
		}
		// Check that the cert type is a valid one.
		if opts.CertType != "" && opts.CertType != SSHHostCert {
			return nil, errs.Forbidden("ssh certificate type does not match - got %v, want %v", opts.CertType, SSHHostCert)
		}

		signOptions = []SignOption{
			// validate is a host certificate and users's KeyID is the subject.
			sshCertOptionsValidator(SignSSHOptions{
				CertType: SSHHostCert,
				KeyID:    claims.Subject,
			}),
			// validates user's SSHOptions with the ones in the token
			sshCertOptionsValidator(*opts),
		}

		// Use options in the token.
		if opts.KeyID != "" {
			keyID = opts.KeyID
		}
		if len(opts.Principals) > 0 {
			principals = opts.Principals
		}

		// Add modifiers from custom claims
		t := now()
		if !opts.ValidAfter.IsZero() {
			signOptions = append(signOptions, sshCertValidAfterModifier(opts.ValidAfter.RelativeTime(t).Unix()))
		}
		if !opts.ValidBefore.IsZero() {
			signOptions = append(signOptions, sshCertValidBeforeModifier(opts.ValidBefore.RelativeTime(t).Unix()))
		}
	}

	// Certificate templates.
	data := sshutil.CreateTemplateData(sshutil.HostCert, keyID, principals)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// The Nebula certificate will be available using the template variable Crt.
	// For example {{ .AuthorizationCrt.Details.Groups }} can be used to get all the groups.
	data.SetAuthorizationCertificate(crt)

	templateOptions, err := TemplateSSHOptions(p.Options, data)
	if err != nil {
		return nil, err
	}

	return append(signOptions,
		p,
		templateOptions,
		// Checks the validity bounds, and set the validity if has not been set.
		&sshLimitDuration{p.ctl.Claimer, crt.Details.NotAfter},
		// Validate public key.
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.ctl.Claimer},
		// Require all the fields in the SSH certificate
		&sshCertDefaultValidator{},
		// Ensure that all principal names are allowed
		newSSHNamePolicyValidator(p.ctl.getPolicy().getSSHHost(), nil),
		// Call webhooks
		p.ctl.newWebhookController(data, linkedca.Webhook_SSH),
	), nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
func (p *Nebula) AuthorizeRenew(ctx context.Context, crt *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, crt)
}

// AuthorizeRevoke returns an error if the token is not valid.
func (p *Nebula) AuthorizeRevoke(_ context.Context, token string) error {
	return p.validateToken(token, p.ctl.Audiences.Revoke)
}

// AuthorizeSSHRevoke returns an error if SSH is disabled or the token is invalid.
func (p *Nebula) AuthorizeSSHRevoke(_ context.Context, token string) error {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return errs.Unauthorized("ssh is disabled for nebula provisioner '%s'", p.Name)
	}
	if _, _, err := p.authorizeToken(token, p.ctl.Audiences.SSHRevoke); err != nil {
		return err
	}
	return nil
}

// AuthorizeSSHRenew returns an unauthorized error.
func (p *Nebula) AuthorizeSSHRenew(context.Context, string) (*ssh.Certificate, error) {
	return nil, errs.Unauthorized("nebula provisioner does not support SSH renew")
}

// AuthorizeSSHRekey returns an unauthorized error.
func (p *Nebula) AuthorizeSSHRekey(context.Context, string) (*ssh.Certificate, []SignOption, error) {
	return nil, nil, errs.Unauthorized("nebula provisioner does not support SSH rekey")
}

func (p *Nebula) validateToken(token string, audiences []string) error {
	_, _, err := p.authorizeToken(token, audiences)
	return err
}

func (p *Nebula) authorizeToken(token string, audiences []string) (*nebula.NebulaCertificate, *jwtPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("failed to parse token"))
	}

	// Extract Nebula certificate
	h, ok := jwt.Headers[0].ExtraHeaders[NebulaCertHeader]
	if !ok {
		return nil, nil, errs.Unauthorized("failed to parse token: nebula header is missing")
	}
	s, ok := h.(string)
	if !ok {
		return nil, nil, errs.Unauthorized("failed to parse token: nebula header is not valid")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("failed to parse token: nebula header is not valid"))
	}
	c, err := nebula.UnmarshalNebulaCertificate(b)
	if err != nil {
		return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("failed to parse nebula certificate: nebula header is not valid"))
	}

	// Validate nebula certificate against CAs
	if valid, err := c.Verify(now(), p.caPool); !valid {
		if err != nil {
			return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("token is not valid: failed to verify certificate against configured CA"))
		}
		return nil, nil, errs.Unauthorized("token is not valid: failed to verify certificate against configured CA")
	}

	var pub interface{}
	if c.Details.IsCA {
		pub = ed25519.PublicKey(c.Details.PublicKey)
	} else {
		pub = x25519.PublicKey(c.Details.PublicKey)
	}

	// Validate token with public key
	var claims jwtPayload
	if err := jose.Verify(jwt, pub, &claims); err != nil {
		return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("token is not valid: signature does not match"))
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: p.Name,
		Time:   now(),
	}, time.Minute); err != nil {
		return nil, nil, errs.UnauthorizedErr(err, errs.WithMessage("token is not valid: invalid claims"))
	}
	// Validate token and subject too.
	if !matchesAudience(claims.Audience, audiences) {
		return nil, nil, errs.Unauthorized("token is not valid: invalid claims")
	}
	if claims.Subject == "" {
		return nil, nil, errs.Unauthorized("token is not valid: subject cannot be empty")
	}

	return c, &claims, nil
}

type nebulaSANsValidator struct {
	Name string
	IPs  []*net.IPNet
}

// Valid verifies that the SANs stored in the validator are contained with those
// requested in the x509 certificate request.
func (v nebulaSANsValidator) Valid(req *x509.CertificateRequest) error {
	dnsNames, ips, emails, uris := x509util.SplitSANs([]string{v.Name})
	if len(req.DNSNames) > 0 {
		if err := dnsNamesValidator(dnsNames).Valid(req); err != nil {
			return err
		}
	}
	if len(req.EmailAddresses) > 0 {
		if err := emailAddressesValidator(emails).Valid(req); err != nil {
			return err
		}
	}
	if len(req.URIs) > 0 {
		if err := urisValidator(uris).Valid(req); err != nil {
			return err
		}
	}
	if len(req.IPAddresses) > 0 {
		for _, ip := range req.IPAddresses {
			var valid bool
			// Check ip in name
			for _, ipInName := range ips {
				if ip.Equal(ipInName) {
					valid = true
					break
				}
			}
			// Check ip network
			if !valid {
				for _, ipNet := range v.IPs {
					if ip.Equal(ipNet.IP) {
						valid = true
						break
					}
				}
			}
			if !valid {
				for _, ipNet := range v.IPs {
					ips = append(ips, ipNet.IP)
				}
				return errs.Forbidden("certificate request contains invalid IP addresses - got %v, want %v", req.IPAddresses, ips)
			}
		}
	}

	return nil
}

type nebulaPrincipalsValidator struct {
	Name string
	IPs  []*net.IPNet
}

// Valid checks that the SignSSHOptions principals contains only names in the
// Nebula certificate.
func (v nebulaPrincipalsValidator) Valid(got SignSSHOptions) error {
	for _, p := range got.Principals {
		var valid bool
		if p == v.Name {
			valid = true
		}
		if !valid {
			if ip := net.ParseIP(p); ip != nil {
				for _, ipnet := range v.IPs {
					if ip.Equal(ipnet.IP) {
						valid = true
						break
					}
				}
			}
		}

		if !valid {
			ips := make([]net.IP, len(v.IPs))
			for i, ipNet := range v.IPs {
				ips[i] = ipNet.IP
			}
			return errs.Forbidden(
				"ssh certificate principals contains invalid name or IP addresses - got %v, want %s or %v",
				got.Principals, v.Name, ips,
			)
		}
	}
	return nil
}
