package provisioner

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// openIDConfiguration contains the necessary properties in the
// `/.well-known/openid-configuration` document.
type openIDConfiguration struct {
	Issuer    string `json:"issuer"`
	JWKSetURI string `json:"jwks_uri"`
}

// Validate validates the values in a well-known OpenID configuration endpoint.
func (c openIDConfiguration) Validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("issuer cannot be empty")
	case c.JWKSetURI == "":
		return errors.New("jwks_uri cannot be empty")
	default:
		return nil
	}
}

// openIDPayload represents the fields on the id_token JWT payload.
type openIDPayload struct {
	jose.Claims
	AtHash          string `json:"at_hash"`
	AuthorizedParty string `json:"azp"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	Hd              string `json:"hd"`
	Nonce           string `json:"nonce"`
}

// OIDC represents an OAuth 2.0 OpenID Connect provider.
//
// ClientSecret is mandatory, but it can be an empty string.
type OIDC struct {
	Type                  string   `json:"type"`
	Name                  string   `json:"name"`
	ClientID              string   `json:"clientID"`
	ClientSecret          string   `json:"clientSecret"`
	ConfigurationEndpoint string   `json:"configurationEndpoint"`
	Admins                []string `json:"admins,omitempty"`
	Domains               []string `json:"domains,omitempty"`
	Claims                *Claims  `json:"claims,omitempty"`
	configuration         openIDConfiguration
	keyStore              *keyStore
}

// IsAdmin returns true if the given email is in the Admins whitelist, false
// otherwise.
func (o *OIDC) IsAdmin(email string) bool {
	email = sanitizeEmail(email)
	for _, e := range o.Admins {
		if email == sanitizeEmail(e) {
			return true
		}
	}
	return false
}

func sanitizeEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		email = email[:i] + strings.ToLower(email[i:])
	}
	return email
}

// GetID returns the provisioner unique identifier, the OIDC provisioner the
// uses the clientID for this.
func (o *OIDC) GetID() string {
	return o.ClientID
}

// GetName returns the name of the provisioner.
func (o *OIDC) GetName() string {
	return o.Name
}

// GetType returns the type of provisioner.
func (o *OIDC) GetType() Type {
	return TypeOIDC
}

// GetEncryptedKey is not available in an OIDC provisioner.
func (o *OIDC) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

// Init validates and initializes the OIDC provider.
func (o *OIDC) Init(config Config) (err error) {
	switch {
	case o.Type == "":
		return errors.New("type cannot be empty")
	case o.Name == "":
		return errors.New("name cannot be empty")
	case o.ClientID == "":
		return errors.New("clientID cannot be empty")
	case o.ConfigurationEndpoint == "":
		return errors.New("configurationEndpoint cannot be empty")
	}

	// Update claims with global ones
	if o.Claims, err = o.Claims.Init(&config.Claims); err != nil {
		return err
	}
	// Decode and validate openid-configuration endpoint
	if err := getAndDecode(o.ConfigurationEndpoint, &o.configuration); err != nil {
		return err
	}
	if err := o.configuration.Validate(); err != nil {
		return errors.Wrapf(err, "error parsing %s", o.ConfigurationEndpoint)
	}
	// Get JWK key set
	o.keyStore, err = newKeyStore(o.configuration.JWKSetURI)
	if err != nil {
		return err
	}
	return nil
}

// ValidatePayload validates the given token payload.
func (o *OIDC) ValidatePayload(p openIDPayload) error {
	// According to "rfc7519 JSON Web Token" acceptable skew should be no more
	// than a few minutes.
	if err := p.ValidateWithLeeway(jose.Expected{
		Issuer:   o.configuration.Issuer,
		Audience: jose.Audience{o.ClientID},
		Time:     time.Now().UTC(),
	}, time.Minute); err != nil {
		return errors.Wrap(err, "failed to validate payload")
	}

	// Validate azp if present
	if p.AuthorizedParty != "" && p.AuthorizedParty != o.ClientID {
		return errors.New("failed to validate payload: invalid azp")
	}

	// Enforce an email claim
	if p.Email == "" {
		return errors.New("failed to validate payload: email not found")
	}

	// Validate domains (case-insensitive)
	if !o.IsAdmin(p.Email) && len(o.Domains) > 0 {
		email := sanitizeEmail(p.Email)
		var found bool
		for _, d := range o.Domains {
			if strings.HasSuffix(email, "@"+strings.ToLower(d)) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("failed to validate payload: email is not allowed")
		}
	}

	return nil
}

// Authorize validates the given token.
func (o *OIDC) Authorize(token string) ([]SignOption, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	// Parse claims to get the kid
	var claims openIDPayload
	if err := jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errors.Wrap(err, "error parsing claims")
	}

	found := false
	kid := jwt.Headers[0].KeyID
	keys := o.keyStore.Get(kid)
	for _, key := range keys {
		if err := jwt.Claims(key, &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("cannot validate token")
	}

	if err := o.ValidatePayload(claims); err != nil {
		return nil, err
	}

	// Admins should be able to authorize any SAN
	if o.IsAdmin(claims.Email) {
		return []SignOption{
			profileDefaultDuration(o.Claims.DefaultTLSCertDuration()),
			newProvisionerExtensionOption(TypeOIDC, o.Name, o.ClientID),
			newValidityValidator(o.Claims.MinTLSCertDuration(), o.Claims.MaxTLSCertDuration()),
		}, nil
	}

	return []SignOption{
		emailOnlyIdentity(claims.Email),
		profileDefaultDuration(o.Claims.DefaultTLSCertDuration()),
		newProvisionerExtensionOption(TypeOIDC, o.Name, o.ClientID),
		newValidityValidator(o.Claims.MinTLSCertDuration(), o.Claims.MaxTLSCertDuration()),
	}, nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (o *OIDC) AuthorizeRenewal(cert *x509.Certificate) error {
	if o.Claims.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", o.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (o *OIDC) AuthorizeRevoke(token string) error {
	return errors.New("not implemented")
}

func getAndDecode(uri string, v interface{}) error {
	resp, err := http.Get(uri)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to %s", uri)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return errors.Wrapf(err, "error reading %s", uri)
	}
	return nil
}
