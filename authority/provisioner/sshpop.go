package provisioner

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
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
	*base
	ID         string  `json:"-"`
	Type       string  `json:"type"`
	Name       string  `json:"name"`
	Claims     *Claims `json:"claims,omitempty"`
	db         db.AuthDB
	claimer    *Claimer
	audiences  Audiences
	sshPubKeys *SSHKeys
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any SSH-POP provisioner.
func (p *SSHPOP) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *SSHPOP) GetIDForToken() string {
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
	case config.SSHKeys == nil:
		return errors.New("provisioner public SSH validation keys cannot be empty")
	}

	// Update claims with global ones
	var err error
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}

	p.audiences = config.Audiences.WithFragment(p.GetIDForToken())
	p.db = config.DB
	p.sshPubKeys = config.SSHKeys
	return nil
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *SSHPOP) authorizeToken(token string, audiences []string) (*sshPOPPayload, error) {
	sshCert, jwt, err := ExtractSSHPOPCert(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err,
			"sshpop.authorizeToken; error extracting sshpop header from token")
	}

	// Check for revocation.
	if isRevoked, err := p.db.IsSSHRevoked(strconv.FormatUint(sshCert.Serial, 10)); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"sshpop.authorizeToken; error checking checking sshpop cert revocation")
	} else if isRevoked {
		return nil, errs.Unauthorized("sshpop.authorizeToken; sshpop certificate is revoked")
	}

	// Check validity period of the certificate.
	n := time.Now()
	if sshCert.ValidAfter != 0 && time.Unix(int64(sshCert.ValidAfter), 0).After(n) {
		return nil, errs.Unauthorized("sshpop.authorizeToken; sshpop certificate validAfter is in the future")
	}
	if sshCert.ValidBefore != 0 && time.Unix(int64(sshCert.ValidBefore), 0).Before(n) {
		return nil, errs.Unauthorized("sshpop.authorizeToken; sshpop certificate validBefore is in the past")
	}
	sshCryptoPubKey, ok := sshCert.Key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errs.InternalServer("sshpop.authorizeToken; sshpop public key could not be cast to ssh CryptoPublicKey")
	}
	pubKey := sshCryptoPubKey.CryptoPublicKey()

	var (
		found bool
		data  = bytesForSigning(sshCert)
		keys  []ssh.PublicKey
	)
	if sshCert.CertType == ssh.UserCert {
		keys = p.sshPubKeys.UserKeys
	} else {
		keys = p.sshPubKeys.HostKeys
	}
	for _, k := range keys {
		if err = (&ssh.Certificate{Key: k}).Verify(data, sshCert.Signature); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errs.Unauthorized("sshpop.authorizeToken; could not find valid ca signer to verify sshpop certificate")
	}

	// Using the ssh certificates key to validate the claims accomplishes two
	// things:
	//   1. Asserts that the private key used to sign the token corresponds
	//      to the public certificate in the `sshpop` header of the token.
	//   2. Asserts that the claims are valid - have not been tampered with.
	var claims sshPOPPayload
	if err = jwt.Claims(pubKey, &claims); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "sshpop.authorizeToken; error parsing sshpop token claims")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: p.Name,
		Time:   time.Now().UTC(),
	}, time.Minute); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "sshpop.authorizeToken; invalid sshpop token")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, audiences) {
		return nil, errs.Unauthorized("sshpop.authorizeToken; sshpop token has invalid audience "+
			"claim (aud): expected %s, but got %s", audiences, claims.Audience)
	}

	if claims.Subject == "" {
		return nil, errs.Unauthorized("sshpop.authorizeToken; sshpop token subject cannot be empty")
	}

	claims.sshCert = sshCert
	return &claims, nil
}

// AuthorizeSSHRevoke validates the authorization token and extracts/validates
// the SSH certificate from the ssh-pop header.
func (p *SSHPOP) AuthorizeSSHRevoke(ctx context.Context, token string) error {
	claims, err := p.authorizeToken(token, p.audiences.SSHRevoke)
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "sshpop.AuthorizeSSHRevoke")
	}
	if claims.Subject != strconv.FormatUint(claims.sshCert.Serial, 10) {
		return errs.BadRequest("sshpop.AuthorizeSSHRevoke; sshpop token subject " +
			"must be equivalent to sshpop certificate serial number")
	}
	return nil
}

// AuthorizeSSHRenew validates the authorization token and extracts/validates
// the SSH certificate from the ssh-pop header.
func (p *SSHPOP) AuthorizeSSHRenew(ctx context.Context, token string) (*ssh.Certificate, error) {
	claims, err := p.authorizeToken(token, p.audiences.SSHRenew)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "sshpop.AuthorizeSSHRenew")
	}
	if claims.sshCert.CertType != ssh.HostCert {
		return nil, errs.BadRequest("sshpop.AuthorizeSSHRenew; sshpop certificate must be a host ssh certificate")
	}

	return claims.sshCert, nil

}

// AuthorizeSSHRekey validates the authorization token and extracts/validates
// the SSH certificate from the ssh-pop header.
func (p *SSHPOP) AuthorizeSSHRekey(ctx context.Context, token string) (*ssh.Certificate, []SignOption, error) {
	claims, err := p.authorizeToken(token, p.audiences.SSHRekey)
	if err != nil {
		return nil, nil, errs.Wrap(http.StatusInternalServerError, err, "sshpop.AuthorizeSSHRekey")
	}
	if claims.sshCert.CertType != ssh.HostCert {
		return nil, nil, errs.BadRequest("sshpop.AuthorizeSSHRekey; sshpop certificate must be a host ssh certificate")
	}
	return claims.sshCert, []SignOption{
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.claimer},
		// Require and validate all the default fields in the SSH certificate.
		&sshCertDefaultValidator{},
	}, nil

}

// ExtractSSHPOPCert parses a JWT and extracts and loads the SSH Certificate
// in the sshpop header. If the header is missing, an error is returned.
func ExtractSSHPOPCert(token string) (*ssh.Certificate, *jose.JSONWebToken, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "extractSSHPOPCert; error parsing token")
	}

	encodedSSHCert, ok := jwt.Headers[0].ExtraHeaders["sshpop"]
	if !ok {
		return nil, nil, errors.New("extractSSHPOPCert; token missing sshpop header")
	}
	encodedSSHCertStr, ok := encodedSSHCert.(string)
	if !ok {
		return nil, nil, errors.Errorf("extractSSHPOPCert; error unexpected type for sshpop header: "+
			"want 'string', but got '%T'", encodedSSHCert)
	}
	sshCertBytes, err := base64.StdEncoding.DecodeString(encodedSSHCertStr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "extractSSHPOPCert; error base64 decoding sshpop header")
	}
	sshPub, err := ssh.ParsePublicKey(sshCertBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "extractSSHPOPCert; error parsing ssh public key")
	}
	sshCert, ok := sshPub.(*ssh.Certificate)
	if !ok {
		return nil, nil, errors.New("extractSSHPOPCert; error converting ssh public key to ssh certificate")
	}
	return sshCert, jwt, nil
}

func bytesForSigning(cert *ssh.Certificate) []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	// Drop trailing signature length.
	return out[:len(out)-4]
}
