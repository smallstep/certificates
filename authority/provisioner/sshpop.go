package provisioner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

// sshPOPPayload extends jwt.Claims with step attributes.
type sshPOPPayload struct {
	jose.Claims
	SANs    []string     `json:"sans,omitempty"`
	Step    *stepPayload `json:"step,omitempty"`
	sshCert *ssh.Certificate
}

// SSHPOP is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type SSHPOP struct {
	Type       string  `json:"type"`
	Name       string  `json:"name"`
	PubKeys    []byte  `json:"pubKeys"`
	Claims     *Claims `json:"claims,omitempty"`
	claimer    *Claimer
	audiences  Audiences
	sshPubKeys []ssh.PublicKey
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any SSH-POP provisioner.
func (p *SSHPOP) GetID() string {
	return "sshpop/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *SSHPOP) GetTokenID(ott string) (string, error) {
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
func (p *SSHPOP) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *SSHPOP) GetType() Type {
	return TypeSSHPOP
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *SSHPOP) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// Init initializes and validates the fields of a SSHPOP type.
func (p *SSHPOP) Init(config Config) error {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case len(p.PubKeys) == 0:
		return errors.New("provisioner root(s) cannot be empty")
	}

	var (
		block *pem.Block
		rest  = p.PubKeys
	)
	for rest != nil {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := pemutil.ParseKey(pem.EncodeToMemory(block))
		if err != nil {
			return errors.Wrapf(err, "error parsing public key in provisioner %s", p.GetID())
		}
		switch q := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			sshKey, err := ssh.NewPublicKey(key)
			if err != nil {
				return errors.Wrap(err, "error converting pub key to SSH pub key")
			}
			p.sshPubKeys = append(p.sshPubKeys, sshKey)
		default:
			return errors.Errorf("Unexpected public key type %T in provisioner %s", q, p.GetID())
		}
	}

	// Verify that at least one root was found.
	if len(p.sshPubKeys) == 0 {
		return errors.Errorf("no root public keys found in pub keys attribute for provisioner %s", p.GetName())
	}

	// Update claims with global ones
	var err error
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}

	p.audiences = config.Audiences.WithFragment(p.GetID())
	return nil
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *SSHPOP) authorizeToken(token string, audiences []string) (*sshPOPPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	encodedSSHCert, ok := jwt.Headers[0].ExtraHeaders["sshpop"]
	if !ok {
		return nil, errors.New("token missing sshpop header")
	}
	encodedSSHCertStr, ok := encodedSSHCert.(string)
	if !ok {
		return nil, errors.New("error unexpected type for sshpop header")
	}
	sshCertBytes, err := base64.RawURLEncoding.DecodeString(encodedSSHCertStr)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding sshpop header")
	}
	sshPub, err := ssh.ParsePublicKey(sshCertBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing ssh public key")
	}
	sshCert, ok := sshPub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("error converting ssh public key to ssh certificate")
	}

	data := bytesForSigning(sshCert)
	var found bool
	for _, k := range p.sshPubKeys {
		if err = (&ssh.Certificate{Key: k}).Verify(data, sshCert.Signature); err == nil {
			found = true
		}
	}
	if !found {
		return nil, errors.New("error: provisioner could could not verify the sshpop header certificate")
	}

	// Using the leaf certificates key to validate the claims accomplishes two
	// things:
	//   1. Asserts that the private key used to sign the token corresponds
	//      to the public certificate in the `sshpop` header of the token.
	//   2. Asserts that the claims are valid - have not been tampered with.
	var claims sshPOPPayload
	if err = jwt.Claims(sshCert.Key, &claims); err != nil {
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

	claims.sshCert = sshCert
	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *SSHPOP) AuthorizeRevoke(token string) error {
	_, err := p.authorizeToken(token, p.audiences.Revoke)
	return err
}

// AuthorizeSign validates the given token.
func (p *SSHPOP) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
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

	return []SignOption{
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeSSHPOP, p.Name, ""),
		profileLimitDuration{p.claimer.DefaultTLSCertDuration(), time.Unix(int64(claims.sshCert.ValidBefore), 0)},
		// validators
		commonNameValidator(claims.Subject),
		defaultPublicKeyValidator{},
		dnsNamesValidator(dnsNames),
		emailAddressesValidator(emails),
		ipAddressesValidator(ips),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	}, nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *SSHPOP) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// authorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *SSHPOP) authorizeSSHSign(claims *sshPOPPayload) ([]SignOption, error) {
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
	t := now()
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
		// Checks the validity bounds, and set the validity if has not been set.
		sshLimitValidityModifier(p.claimer, time.Unix(int64(claims.sshCert.ValidBefore), 0)),
		// Validate public key.
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertificateValidityValidator{p.claimer},
		// Require all the fields in the SSH certificate
		&sshCertificateDefaultValidator{},
	), nil
}

func bytesForSigning(cert *ssh.Certificate) []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	// Drop trailing signature length.
	return out[:len(out)-4]
}
